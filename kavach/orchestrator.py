from __future__ import annotations

from typing import Any

from .cve_input import (
    CVEExploitInput,
    CVEInputValidationError,
    apply_cve_input_to_state,
    load_cve_input,
    parse_cve_input,
)
from .agents import (
    BuilderAgent,
    CollectorAgent,
    ExploiterAgent,
    JudgeAgent,
    ResearcherAgent,
    VerifierAgent,
)
from .config import get_config
from .database import RunStore
from .llm_client import make_llm
from .logging_utils import RunLogger
from .recipe import AutoRecipeGenerator
from .report import render_log_report
from .schemas import PipelineState, Stage

# Defensive pipeline: benign verification only.
# (LangGraph maps each entry to a node; this stdlib runner keeps the same shape
# while remaining dependency-free for demos and CI.)
DEFENSIVE_PIPELINE = [
    ("collector", CollectorAgent),
    ("researcher", ResearcherAgent),
    ("builder", BuilderAgent),
    ("verifier", VerifierAgent),
    ("judge", JudgeAgent),
]

# Offensive pipeline: adds the Exploiter (real PoC + flag capture) before the
# Verifier/Judge. Only runs against authorized targets (lab twin or allowlisted).
OFFENSIVE_PIPELINE = [
    ("collector", CollectorAgent),
    ("researcher", ResearcherAgent),
    ("builder", BuilderAgent),
    ("exploiter", ExploiterAgent),
    ("verifier", VerifierAgent),
    ("judge", JudgeAgent),
]


class Orchestrator:
    """Drives a CVE through the five agents, with retries and persistence."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or get_config()
        self.llm = make_llm(self.config)
        self.store = RunStore(self.config["db_path"])
        self.max_retries = int(self.config.get("max_agent_retries", 2))
        self.mode = self.config.get("mode", "defensive")
        pipeline = OFFENSIVE_PIPELINE if self.mode == "offensive" else DEFENSIVE_PIPELINE
        self._agents = [(name, cls(self.llm, self.config)) for name, cls in pipeline]

    def analyze(
        self,
        cve_id: str,
        repo_url: str = "",
        target: str = "",
        cve_input: CVEExploitInput | None = None,
        cve_json_path: str = "",
        auto_recipe: bool = False,
    ) -> PipelineState:
        if cve_json_path and cve_input is None:
            cve_input = load_cve_input(cve_json_path)

        effective_id = (cve_input.id if cve_input else cve_id).upper()
        state = PipelineState(
            cve_id=effective_id,
            repo_url=repo_url,
            mode=self.mode,
            target=target or self.config.get("authorized_target", ""),
        )

        run_logger: RunLogger | None = None
        want_logs = bool(
            self.config.get("verbose")
            or self.mode == "offensive"
            or auto_recipe
            or self.config.get("auto_recipe")
            or cve_input is not None
        )
        if want_logs:
            agent_label = (state.cve_id or "run").lower()
            run_logger = RunLogger(
                state.run_id,
                self.config["runs_dir"],
                verbose=bool(self.config.get("verbose")),
                agent=agent_label,
            )
            state.log_file = run_logger.log_file
            self.config["run_logger"] = run_logger
            run_logger.log(
                "orchestrator",
                "run started",
                llm_mode=self.config["llm_mode"],
                provider=self.config["provider"]["name"],
                model=self.config["model"],
                mode=state.mode,
                auto_recipe=bool(auto_recipe or self.config.get("auto_recipe")),
                log_file=run_logger.log_file,
            )
            if self.config.get("verbose"):
                print(
                    f"[kavach] live log → {run_logger.log_file}",
                    file=__import__("sys").stderr,
                )

        # Auto mode: generate the exploit recipe from the CVE before exploitation
        # itself (collect -> research swarm -> recipe JSON) when none is supplied.
        if cve_input is None and (auto_recipe or self.config.get("auto_recipe")):
            if run_logger:
                run_logger.phase_start("auto_recipe", state.cve_id)
            cve_input = self._auto_generate_recipe(
                cve_id, repo_url, target, run_logger=run_logger
            )
            if run_logger:
                run_logger.phase_end(
                    "auto_recipe",
                    "recipe ready" if cve_input else "recipe generation failed",
                    ok=bool(cve_input),
                )

        if cve_input is not None:
            self._apply_cve_input(state, cve_input)

        self._enrich_thin_cve_context(state)

        enriched_intel = False

        state.log(
            "orchestrator",
            "run started",
            llm_mode=self.config["llm_mode"],
            mode=state.mode,
            cve_json=bool(cve_input),
        )
        self.store.save(state)

        for name, agent in self._agents:
            if name == "verifier" and self.config.get("skip_verifier"):
                state.log("verifier", "skipped (exploit-only mode)")
                if run_logger:
                    run_logger.log("orchestrator", "agent skipped: verifier (exploit-only)")
                continue
            if name == "exploiter" and not enriched_intel and self.config.get("serpapi_api_key"):
                from .search.intel import enrich_state_from_web_search

                if run_logger:
                    run_logger.phase_start("web_intel")
                enrich_state_from_web_search(state, self.llm, self.config)
                enriched_intel = True
                if run_logger:
                    run_logger.phase_end(
                        "web_intel",
                        "google search complete",
                        paths=len((state.web_intel or {}).get("probe_paths") or []),
                    )
            if run_logger:
                run_logger.phase_start(f"agent:{name}")
            ok = self._run_agent(agent, name, state, run_logger)
            self.store.save(state)
            if not ok or state.stage == Stage.FAILED.value:
                state.stage = Stage.FAILED.value
                if run_logger:
                    run_logger.phase_end(f"agent:{name}", "halted")
                    run_logger.log("orchestrator", f"halted at {name}")
                state.log("orchestrator", f"halted at {name}")
                self.store.save(state)
                if run_logger:
                    self._append_run_report(run_logger, state)
                    run_logger.close()
                return state
            if run_logger:
                run_logger.phase_end(f"agent:{name}", f"stage={state.stage}")

        if state.stage not in (Stage.DONE.value, Stage.NEEDS_REVIEW.value):
            state.stage = Stage.DONE.value
        if run_logger:
            run_logger.log("orchestrator", "run finished", stage=state.stage)
        state.log("orchestrator", "run finished", stage=state.stage)
        self.store.save(state)
        if run_logger:
            self._append_run_report(run_logger, state)
            run_logger.close()
        return state

    def _append_run_report(self, run_logger: RunLogger, state: PipelineState) -> None:
        run_logger.append_report(render_log_report(state, self.config))

    def _auto_generate_recipe(
        self,
        cve_id: str,
        repo_url: str,
        target: str,
        *,
        run_logger: RunLogger | None = None,
    ) -> CVEExploitInput | None:
        """Collect + research the CVE, then synthesize a validated exploit recipe."""
        scratch = PipelineState(cve_id=cve_id.upper(), repo_url=repo_url, mode="offensive")
        try:
            if run_logger:
                run_logger.phase_start("auto_recipe:collector")
            CollectorAgent(self.llm, self.config).run(scratch)
            if run_logger:
                src = scratch.cve_context.source if scratch.cve_context else "none"
                run_logger.phase_end("auto_recipe:collector", f"source={src}")
            if scratch.cve_context is None:
                return None
            if run_logger:
                run_logger.phase_start("auto_recipe:researcher")
            ResearcherAgent(self.llm, self.config).run(scratch)
            if run_logger:
                vc = scratch.research_memo.vulnerability_class if scratch.research_memo else "?"
                run_logger.phase_end("auto_recipe:researcher", f"class={vc}")
            if scratch.research_memo is None:
                return None
            if run_logger:
                run_logger.phase_start("auto_recipe:recipe_swarm")
            recipe = AutoRecipeGenerator(self.llm, self.config).generate(
                scratch.cve_context, scratch.research_memo
            )
            if run_logger:
                run_logger.phase_end("auto_recipe:recipe_swarm", "validated recipe JSON")
            # Operator-supplied target overrides the recipe's lab default.
            if target:
                recipe.setdefault("authorization", {})["target_url"] = target
            return parse_cve_input(recipe)
        except CVEInputValidationError:
            return None
        except Exception:  # noqa: BLE001 - never let recipe-gen crash the run
            return None

    def _apply_cve_input(self, state: PipelineState, cve_input: CVEExploitInput) -> None:
        """Pre-fill pipeline state from operator JSON and switch to offensive mode."""
        ctx, memo, artifact = apply_cve_input_to_state(cve_input)
        state.cve_id = cve_input.id
        state.cve_context = ctx
        state.research_memo = memo
        state.build_artifact = artifact
        state.cve_input = cve_input.to_dict()
        state.mode = "offensive"
        self.mode = "offensive"
        self._agents = [
            (name, cls(self.llm, self.config))
            for name, cls in OFFENSIVE_PIPELINE
        ]

        if cve_input.target_url and not state.target:
            state.target = cve_input.target_url
        if cve_input.serve_lab:
            self.config["serve_lab"] = True
        if cve_input.exploit_only or self.config.get("skip_verifier"):
            self.config["skip_verifier"] = True
        if cve_input.operator_confirms_authorized and cve_input.target_url:
            self.config["authorized_target"] = cve_input.target_url

        state.log(
            "orchestrator",
            "loaded CVE JSON input",
            id=cve_input.id,
            disclosure=cve_input.disclosure_status,
            target=state.target,
        )

    def _enrich_thin_cve_context(self, state: PipelineState) -> None:
        """When exploit-only JSON is minimal, pull public offline sample context (no paths hardcoded)."""
        ctx = state.cve_context
        memo = state.research_memo
        if not ctx or len((ctx.description or "").strip()) >= 80:
            return
        if not self.config.get("offline"):
            return
        sample = CollectorAgent(self.llm, self.config)._collect(state.cve_id.upper())
        if not sample or sample.source != "offline-sample":
            return
        ctx.description = sample.description or ctx.description
        if sample.cwe_ids:
            ctx.cwe_ids = list(sample.cwe_ids)
        for ref in sample.references:
            if ref not in ctx.references:
                ctx.references.append(ref)
        if memo:
            memo.vulnerability_class = ResearcherAgent._classify(
                sample.cwe_ids, sample.description
            )
            memo.root_cause = (sample.description or memo.root_cause)[:240]
            memo.attack_scenario = (sample.description or memo.attack_scenario)[:400]
            memo.summary = (sample.description or memo.summary)[:200]
        state.log(
            "orchestrator",
            "enriched minimal CVE JSON from offline public sample",
            vuln_class=memo.vulnerability_class if memo else "",
        )

    def _run_agent(
        self,
        agent: Any,
        name: str,
        state: PipelineState,
        run_logger: RunLogger | None = None,
    ) -> bool:
        attempts = self.max_retries + 1
        for attempt in range(1, attempts + 1):
            try:
                agent.run(state)
                if state.errors and name == "collector" and state.cve_context is None:
                    return False
                return True
            except Exception as exc:  # noqa: BLE001 - retry then record failure
                msg = f"attempt {attempt}/{attempts} failed: {exc}"
                if run_logger:
                    run_logger.log(name, msg)
                state.log(name, msg)
                if attempt >= attempts:
                    state.errors.append(f"{name} failed: {exc}")
                    return False
        return False
