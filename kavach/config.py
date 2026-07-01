from __future__ import annotations

import os
from pathlib import Path
from typing import Any

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent
PROMPTS_DIR = PACKAGE_DIR / "prompts"


def _load_env_file(path: Path) -> None:
    """Load KEY=VALUE lines from a .env file into os.environ (no overwrite)."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if " #" in value:
            value = value.split(" #", 1)[0].strip()
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file(PROJECT_DIR / ".env")

# OpenAI-compatible providers for self-hostable / open models.
PROVIDERS: dict[str, dict[str, str]] = {
    "Together": {
        "name": "Together",
        "key_env": "TOGETHER_API_KEY",
        "base_url": "https://api.together.xyz/v1",
    },
    "Cerebras": {
        "name": "Cerebras",
        "key_env": "CEREBRAS_API_KEY",
        "base_url": "https://api.cerebras.ai/v1",
    },
    "Fireworks": {
        "name": "Fireworks",
        "key_env": "FIREWORKS_API_KEY",
        "base_url": "https://api.fireworks.ai/inference/v1",
    },
    "Local": {
        # Any OpenAI-compatible local server (vLLM, Ollama, LM Studio, etc.).
        "name": "Local",
        "key_env": "KAVACH_LOCAL_API_KEY",
        "base_url": os.getenv("KAVACH_LOCAL_BASE_URL", "http://localhost:8001/v1"),
    },
}

DATA_DIR = PROJECT_DIR / "data"
RUNS_DIR = DATA_DIR / "runs"
DATA_DIR.mkdir(exist_ok=True)
RUNS_DIR.mkdir(exist_ok=True)


def get_config() -> dict[str, Any]:
    """Return the full runtime configuration, sourced from env with defaults."""
    provider_name = os.getenv("KAVACH_PROVIDER", "Together")
    provider = PROVIDERS.get(provider_name, PROVIDERS["Together"])

    # llm_mode: "mock" runs fully offline with deterministic templated output
    # (great for demos/tests/CI); "live" calls the configured provider.
    llm_mode = os.getenv("KAVACH_LLM_MODE", "mock").lower()

    return {
        "provider": provider,
        "llm_mode": llm_mode,
        "model": os.getenv("KAVACH_MODEL", "meta-llama/Llama-3.3-70B-Instruct-Turbo"),
        "temperature": float(os.getenv("KAVACH_TEMPERATURE", "0.2")),
        "max_tokens": int(os.getenv("KAVACH_MAX_TOKENS", "2048")),
        # Data sources
        "nvd_api_base": os.getenv("KAVACH_NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        "nvd_api_key": os.getenv("KAVACH_NVD_API_KEY", ""),
        "serpapi_api_key": os.getenv("SERPAPI_API_KEY", ""),
        "offline": os.getenv("KAVACH_OFFLINE", "true").lower() == "true",
        # Sandbox
        "sandbox_enabled": os.getenv("KAVACH_SANDBOX_ENABLED", "false").lower() == "true",
        "sandbox_image_prefix": os.getenv("KAVACH_SANDBOX_IMAGE_PREFIX", "kavach-sandbox"),
        "sandbox_timeout_secs": int(os.getenv("KAVACH_SANDBOX_TIMEOUT", "120")),
        "seccomp_profile": str(PACKAGE_DIR / "sandbox" / "seccomp.json"),
        # Mode & exploitation
        # "defensive" (default) runs benign verification only.
        # "offensive" enables the Exploiter agent to generate a real PoC and run
        # it against an AUTHORIZED target (local lab twin or an allowed URL).
        "mode": os.getenv("KAVACH_MODE", "defensive").lower(),
        "authorized_target": os.getenv("KAVACH_AUTHORIZED_TARGET", ""),
        # Extra hostnames the operator has authorization to test, comma-separated.
        # localhost / loopback / RFC1918 are always allowed for lab use.
        "target_allowlist": [
            h.strip().lower()
            for h in os.getenv("KAVACH_TARGET_ALLOWLIST", "").split(",")
            if h.strip()
        ],
        "exploit_max_iterations": int(os.getenv("KAVACH_EXPLOIT_MAX_ITERATIONS", "3")),
        "skip_verifier": os.getenv("KAVACH_SKIP_VERIFIER", "false").lower() == "true",
        "serve_lab": os.getenv("KAVACH_SERVE_LAB", "false").lower() == "true",
        "lab_port": int(os.getenv("KAVACH_LAB_PORT", "8080")),
        "verbose": os.getenv("KAVACH_VERBOSE", "").lower() == "true",
        # Orchestration
        "max_agent_retries": int(os.getenv("KAVACH_MAX_AGENT_RETRIES", "2")),
        # Storage
        "db_path": os.getenv("KAVACH_DB_PATH", str(DATA_DIR / "kavach.db")),
        "runs_dir": str(RUNS_DIR),
        # Safety
        "human_review_required": os.getenv("KAVACH_HUMAN_REVIEW", "false").lower() == "true",
    }
