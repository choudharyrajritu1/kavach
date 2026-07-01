from __future__ import annotations

import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

_SAFE = re.compile(r"[^\w.-]+")


def make_run_log_path(runs_dir: str, agent: str) -> Path:
    """Flat log file: data/runs/<agent>_<YYYY-MM-DD>_<HH-MM-SS>.log"""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    label = _SAFE.sub("_", (agent or "run").strip()).strip("_") or "run"
    root = Path(runs_dir)
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{label}_{stamp}.log"


def log_activity(config: dict[str, Any], category: str, message: str, **extra: Any) -> None:
    """Write a timed activity line when a RunLogger is attached to config."""
    logger = config.get("run_logger")
    if isinstance(logger, RunLogger):
        logger.activity(category, message, **extra)


class RunLogger:
    """Single audit log per run as a flat file in runs_dir.

    Filename pattern: ``<agent>_<YYYY-MM-DD>_<HH-MM-SS>.log`` (no per-run subfolders).

    With verbose=True, streams a live summary to stderr while the run executes.
    Every line includes elapsed wall time since the run started.
    """

    def __init__(
        self,
        run_id: str,
        runs_dir: str,
        *,
        verbose: bool = False,
        agent: str = "run",
        log_path: Path | None = None,
    ) -> None:
        self.run_id = run_id
        self.verbose = verbose
        self.agent = agent
        self.log_path = log_path or make_run_log_path(runs_dir, agent)
        self._fh: TextIO | None = None
        self._started = time.monotonic()
        self._phase_started: dict[str, float] = {}

    def _open(self) -> TextIO:
        if self._fh is None:
            self._fh = self.log_path.open("a", encoding="utf-8")
            self._fh.write(
                f"[{self._ts()}] [+0.0s] [run] id={self.run_id!r} agent={self.agent!r} "
                f"log_file={self.log_path}\n"
            )
            self._fh.flush()
        return self._fh

    def _ts(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def elapsed_s(self) -> float:
        return time.monotonic() - self._started

    def _elapsed_str(self) -> str:
        secs = self.elapsed_s()
        if secs < 60:
            return f"+{secs:.1f}s"
        mins = int(secs // 60)
        rem = secs - mins * 60
        return f"+{mins}m{rem:.0f}s"

    def _write(self, text: str, *, live: bool = False) -> None:
        to_file = text if text.endswith("\n") else text + "\n"
        self._open().write(to_file)
        self._open().flush()
        if self.verbose and live:
            sys.stderr.write(to_file)
            sys.stderr.flush()

    def log(self, agent: str, message: str, **extra: Any) -> None:
        extra_s = " ".join(f"{k}={v!r}" for k, v in extra.items()) if extra else ""
        line = (
            f"[{self._ts()}] [{self._elapsed_str()}] [{agent}] {message}"
            + (f" {extra_s}" if extra_s else "")
        )
        self._write(line, live=True)

    def activity(self, category: str, message: str, **extra: Any) -> None:
        """One-line progress for sub-steps (LLM, HTTP, search, etc.)."""
        extra_s = " ".join(f"{k}={v!r}" for k, v in extra.items()) if extra else ""
        line = (
            f"[{self._ts()}] [{self._elapsed_str()}] [{category}] {message}"
            + (f" {extra_s}" if extra_s else "")
        )
        self._write(line, live=True)

    def phase_start(self, phase: str, detail: str = "") -> None:
        self._phase_started[phase] = time.monotonic()
        msg = f"START {phase}" + (f" — {detail}" if detail else "")
        self.activity("phase", msg)

    def phase_end(self, phase: str, detail: str = "", **extra: Any) -> None:
        t0 = self._phase_started.pop(phase, None)
        duration = round(time.monotonic() - t0, 2) if t0 is not None else None
        if duration is not None:
            extra = {**extra, "duration_s": duration}
        msg = f"END {phase}" + (f" — {detail}" if detail else "")
        self.activity("phase", msg, **extra)

    def exploit(self, iteration: int, message: str, **extra: Any) -> None:
        """Short one-line exploit progress (also written inside iteration blocks)."""
        extra_s = " ".join(f"{k}={v!r}" for k, v in extra.items()) if extra else ""
        line = (
            f"[{self._ts()}] [{self._elapsed_str()}] [exploit iter={iteration}] {message}"
            + (f" {extra_s}" if extra_s else "")
        )
        self._write(line, live=True)

    def iteration_begin(self, iteration: int, max_iter: int, cve_id: str, target: str) -> None:
        banner = (
            f"\n{'=' * 72}\n"
            f"ITERATION {iteration} / {max_iter}  |  {cve_id}  |  target={target}\n"
            f"{'=' * 72}\n"
        )
        self._write(banner, live=True)
        if self.verbose:
            print(
                f"\n>>> [{self._elapsed_str()}] ITERATION {iteration}/{max_iter} — "
                f"calling LLM for exploit plan...",
                file=sys.stderr,
            )

    def iteration_section(self, iteration: int, title: str, body: str) -> None:
        """Detailed block for one aspect of an iteration (file only, unless short)."""
        header = f"--- {title} (iter {iteration}) ---\n"
        content = body if body.endswith("\n") else body + "\n"
        self._write(header + content)

        if self.verbose:
            preview = body.strip()
            if len(preview) > 400:
                preview = preview[:400] + "..."
            print(f"  [{title}]", preview.replace("\n", " "), file=sys.stderr)

    def iteration_end(self, iteration: int, success: bool, summary: str) -> None:
        status = "SUCCESS" if success else "FAILED"
        line = f"--- END ITERATION {iteration}: {status} — {summary} ---\n"
        self._write(line, live=True)
        if self.verbose:
            mark = "✓" if success else "✗"
            print(
                f">>> [{self._elapsed_str()}] {mark} ITERATION {iteration} {status}: {summary}",
                file=sys.stderr,
            )

    def append_report(self, body: str) -> None:
        """Append the final human-readable report once (file only, not stderr)."""
        if not body.strip():
            return
        footer = "=" * 80
        block = f"\n{footer}\n{body.rstrip()}\n{footer}\n"
        self._write(block)
        if self.verbose:
            print(
                f"\n[{self._elapsed_str()}] Report summary appended to {self.log_path}",
                file=sys.stderr,
            )

    def close(self) -> None:
        if self._fh is not None:
            self.activity("run", "log closed", total_s=round(self.elapsed_s(), 1))
            self._fh.close()
            self._fh = None

    @property
    def log_file(self) -> str:
        return str(self.log_path)


class LoggingLLM:
    """Wraps an LLM client and logs each API call with duration to RunLogger."""

    def __init__(self, inner: Any, config: dict[str, Any]) -> None:
        self._inner = inner
        self._config = config
        self.model_name = getattr(inner, "model_name", "unknown")

    @staticmethod
    def _role_hint(system: str) -> str:
        first = (system or "").split("\n", 1)[0].strip()
        if "EXPLOITER verification" in system:
            return "exploiter_confirm"
        if "EXPLOITER agent" in system:
            return "exploiter_plan"
        if "enumerating concrete HTTP" in system:
            return "exploiter_enumerate"
        if "extract exploitation intelligence" in system:
            return "web_intel_extractor"
        if len(first) > 64:
            return first[:64] + "…"
        return first or "llm"

    def complete(self, system: str, user: str) -> str:
        role = self._role_hint(system)
        logger = self._config.get("run_logger")
        if isinstance(logger, RunLogger):
            logger.activity(
                "llm",
                f"calling {role}",
                model=self.model_name,
                prompt_chars=len(user),
            )
        t0 = time.monotonic()
        try:
            result = self._inner.complete(system, user)
        except Exception as exc:
            if isinstance(logger, RunLogger):
                logger.activity(
                    "llm",
                    f"failed {role}",
                    duration_s=round(time.monotonic() - t0, 2),
                    error=str(exc)[:240],
                )
            raise
        if isinstance(logger, RunLogger):
            logger.activity(
                "llm",
                f"done {role}",
                duration_s=round(time.monotonic() - t0, 2),
                response_chars=len(result),
            )
        return result
