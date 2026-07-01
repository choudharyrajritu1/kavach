from __future__ import annotations

from typing import Any

from ..llm_client import LLM
from ..prompts import load_prompt
from ..schemas import PipelineState


class BaseAgent:
    """Common scaffolding for pipeline agents.

    Each agent owns a name, a system prompt, and a ``run`` method that mutates
    and returns the shared :class:`PipelineState`.
    """

    name: str = "base"
    prompt_name: str = ""

    def __init__(self, llm: LLM, config: dict[str, Any]) -> None:
        self.llm = llm
        self.config = config

    @property
    def system_prompt(self) -> str:
        return load_prompt(self.prompt_name) if self.prompt_name else ""

    def ask(self, user: str) -> str:
        """Single-shot LLM call with this agent's system prompt."""
        return self.llm.complete(self.system_prompt, user)

    def run(self, state: PipelineState) -> PipelineState:  # pragma: no cover - abstract
        raise NotImplementedError
