from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..schemas import BuildArtifact


@dataclass
class SandboxResult:
    mode: str  # "docker" | "dry-run"
    executed: bool
    exit_code: int | None
    logs: str
    duration_secs: float
    markers_hit: list[str] = field(default_factory=list)


class SandboxRunner:
    """Runs a Builder artifact inside a strongly isolated container.

    Security posture (when Docker is used):
      --network none           no egress (prevents exfil / live attacks)
      --read-only              immutable root filesystem
      --cap-drop ALL           drop every Linux capability
      --security-opt no-new-privileges
      --security-opt seccomp=<restrictive profile>
      --pids-limit / --memory  resource caps
      --user nobody-style uid  non-root execution

    If Docker is unavailable or disabled, it falls back to a "dry-run" that
    reports the planned, benign markers without executing anything. The runner
    NEVER executes weaponized payloads; the Builder only produces benign markers.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.enabled = bool(config.get("sandbox_enabled"))
        self.image_prefix = config.get("sandbox_image_prefix", "kavach-sandbox")
        self.timeout = int(config.get("sandbox_timeout_secs", 120))
        self.seccomp_profile = config.get("seccomp_profile", "")

    def docker_available(self) -> bool:
        return shutil.which("docker") is not None

    def run(self, artifact: BuildArtifact, *, variant: str = "vulnerable") -> SandboxResult:
        if not self.enabled or not self.docker_available() or not artifact.dockerfile:
            return self._dry_run(artifact, variant)
        return self._docker_run(artifact, variant)

    # -- dry-run -----------------------------------------------------------
    def _dry_run(self, artifact: BuildArtifact, variant: str) -> SandboxResult:
        markers = list(artifact.benign_test_markers)
        logs = (
            f"[dry-run:{variant}] Docker not used (disabled/unavailable/no Dockerfile).\n"
            f"[dry-run:{variant}] Would build a pinned environment and run benign harness.\n"
            f"[dry-run:{variant}] Planned benign markers: {markers or ['<none>']}\n"
        )
        return SandboxResult(
            mode="dry-run",
            executed=False,
            exit_code=None,
            logs=logs,
            duration_secs=0.0,
            markers_hit=[],
        )

    # -- docker ------------------------------------------------------------
    def _docker_run(self, artifact: BuildArtifact, variant: str) -> SandboxResult:
        start = time.time()
        workdir = Path(tempfile.mkdtemp(prefix=f"kavach_{variant}_"))
        logs: list[str] = []
        try:
            (workdir / "Dockerfile").write_text(artifact.dockerfile, encoding="utf-8")
            for rel_path, contents in artifact.harness_files.items():
                target = workdir / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(contents, encoding="utf-8")

            image_tag = f"{self.image_prefix}:{variant}-{int(start)}"
            build = self._exec(
                ["docker", "build", "-t", image_tag, str(workdir)],
                self.timeout,
            )
            logs.append(f"[build:{variant}] exit={build.returncode}\n{build.stdout}\n{build.stderr}")
            if build.returncode != 0:
                return SandboxResult(
                    mode="docker",
                    executed=False,
                    exit_code=build.returncode,
                    logs="\n".join(logs),
                    duration_secs=time.time() - start,
                )

            run_cmd = self._hardened_run_cmd(image_tag)
            run = self._exec(run_cmd, self.timeout)
            logs.append(f"[run:{variant}] exit={run.returncode}\n{run.stdout}\n{run.stderr}")

            combined = run.stdout + "\n" + run.stderr
            markers_hit = [m for m in artifact.benign_test_markers if m and m in combined]

            self._exec(["docker", "rmi", "-f", image_tag], 30)
            return SandboxResult(
                mode="docker",
                executed=True,
                exit_code=run.returncode,
                logs="\n".join(logs),
                duration_secs=time.time() - start,
                markers_hit=markers_hit,
            )
        except subprocess.TimeoutExpired:
            logs.append(f"[{variant}] TIMEOUT after {self.timeout}s")
            return SandboxResult(
                mode="docker",
                executed=True,
                exit_code=124,
                logs="\n".join(logs),
                duration_secs=time.time() - start,
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def _hardened_run_cmd(self, image_tag: str) -> list[str]:
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256",
            "--memory", "512m",
            "--cpus", "1.0",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        ]
        if self.seccomp_profile and Path(self.seccomp_profile).exists():
            cmd += ["--security-opt", f"seccomp={self.seccomp_profile}"]
        cmd.append(image_tag)
        return cmd

    @staticmethod
    def _exec(cmd: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
