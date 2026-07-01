from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=None)
def load_prompt(name: str) -> str:
    """Load a prompt template by stem (e.g. 'collector')."""
    path = _PROMPTS_DIR / f"{name}.txt"
    if not path.exists():
        raise FileNotFoundError(f"Prompt not found: {path}")
    return path.read_text(encoding="utf-8")
