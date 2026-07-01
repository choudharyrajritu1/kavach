#!/usr/bin/env python3
"""KAVACH CLI — Knowledge-driven Autonomous Vulnerability Analysis & Containment Hub.

Examples:
    python run.py CVE-2021-44228
    python run.py CVE-2014-0160 --json
    KAVACH_LLM_MODE=live KAVACH_PROVIDER=Together python run.py CVE-2021-44228
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from kavach.config import get_config  # noqa: E402
from kavach.cve_input import load_cve_input, CVEInputValidationError  # noqa: E402
from kavach.orchestrator import Orchestrator  # noqa: E402
from kavach.safety import authorize_target  # noqa: E402
from kavach.report import render_markdown  # noqa: E402
from kavach.schemas import PipelineState  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="KAVACH — CVE analysis & authorized exploitation pipeline"
    )
    parser.add_argument("cve_id", nargs="?", default="", help="CVE identifier, e.g. CVE-2021-44228")
    parser.add_argument("--repo", default="", help="Optional project/repo URL")
    parser.add_argument(
        "--mode",
        choices=["defensive", "offensive"],
        default="",
        help="defensive (benign verify) or offensive (generate+run a real PoC)",
    )
    parser.add_argument(
        "--target",
        default="",
        help="Authorized target URL for offensive mode (must be lab/loopback or allowlisted)",
    )
    parser.add_argument(
        "--authorized-target",
        action="store_true",
        help="Confirm you are authorized to test --target (required for non-lab hosts)",
    )
    parser.add_argument(
        "--lab",
        action="store_true",
        help="Offensive mode + auto-start bundled vulnerable lab (CVE-2099-00001)",
    )
    parser.add_argument(
        "--serve-lab",
        action="store_true",
        help="Auto-start the bundled vulnerable lab on --target port (default 8080) before exploiting",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Stream live exploit progress to terminal (default ON for offensive/CVE JSON runs)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Disable live terminal streaming",
    )
    parser.add_argument(
        "--cve-json",
        default="",
        help="Path to structured CVE/0-day JSON (see schemas/cve_exploit_input.schema.json)",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Auto-generate the exploit recipe from the CVE (collect -> research swarm -> recipe) then exploit",
    )
    parser.add_argument("--json", action="store_true", help="Emit full state as JSON")
    parser.add_argument("--save", default="", help="Write the markdown report to this path")
    args = parser.parse_args(argv)

    config = get_config()

    if args.auto:
        config["mode"] = "offensive"
        config["auto_recipe"] = True

    cve_json_path = args.cve_json
    if cve_json_path:
        try:
            cve_input_preview = load_cve_input(cve_json_path)
        except CVEInputValidationError as exc:
            parser.error(str(exc))
        config["mode"] = "offensive"
        if cve_input_preview.serve_lab:
            config["serve_lab"] = True
        if cve_input_preview.exploit_only:
            config["skip_verifier"] = True
        if not args.cve_id:
            args.cve_id = cve_input_preview.id
        if cve_input_preview.exploit_only and not args.target and not cve_input_preview.target_url:
            parser.error(
                "exploit-only CVE JSON requires --target URL "
                "(e.g. --target http://127.0.0.1:3100/api/hello)"
            )

    cve_id = args.cve_id
    if args.lab:
        config["mode"] = "offensive"
        config["serve_lab"] = True
        if not cve_id:
            cve_id = "CVE-2099-00001"
    if args.mode:
        config["mode"] = args.mode
    if args.quiet:
        config["verbose"] = False
    elif args.verbose:
        config["verbose"] = True
    else:
        # Live terminal output by default for exploit runs
        config["verbose"] = bool(
            config.get("mode") == "offensive"
            or args.cve_json
            or args.lab
            or args.serve_lab
            or args.auto
            or args.mode == "offensive"
        )
    if args.serve_lab:
        config["serve_lab"] = True
    if not cve_id:
        parser.error("a CVE id is required (or use --lab)")

    # Parse lab port from --target if provided (e.g. http://127.0.0.1:8080/)
    if args.target:
        from urllib.parse import urlparse
        parsed = urlparse(args.target if "://" in args.target else f"http://{args.target}")
        if parsed.port:
            config["lab_port"] = parsed.port

    # Authorization gate: non-lab targets require explicit operator confirmation.
    if args.target:
        config["mode"] = "offensive"
        auth = authorize_target(
            args.target,
            allowlist=config.get("target_allowlist"),
            explicit_authorized=config.get("authorized_target", ""),
        )
        if auth.kind == "authorized_url" and not args.authorized_target:
            parser.error(
                f"target '{args.target}' requires --authorized-target to confirm you are "
                "authorized to test it."
            )
        if not auth.allowed and not args.authorized_target:
            parser.error(
                f"target '{args.target}' is not permitted: {auth.reason}. "
                "Use a loopback/lab target, add it to KAVACH_TARGET_ALLOWLIST, or pass "
                "--authorized-target to assert authorization."
            )
        if args.authorized_target:
            config["authorized_target"] = args.target

    state = Orchestrator(config).analyze(
        cve_id.upper() if cve_id else "",
        args.repo,
        target=args.target,
        cve_json_path=cve_json_path,
        auto_recipe=args.auto,
    )

    if args.json:
        print(json.dumps(state.to_dict(), indent=2))
    else:
        report_md = render_markdown(state, config)
        print(report_md)
        if args.save:
            Path(args.save).write_text(report_md, encoding="utf-8")
            print(f"\n[saved] {args.save}", file=sys.stderr)

    return 0 if state.stage in ("done", "needs_review") else 1


if __name__ == "__main__":
    raise SystemExit(main())
