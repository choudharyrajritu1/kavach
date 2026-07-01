from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Protocol

# Hybrid reasoning models that hide content unless thinking is disabled.
_THINKING_MODEL_MARKERS = (
    "qwen3",
    "kimi-k2",
    "glm-5",
    "deepseek-v4",
    "nemotron-3",
    "cogito-v2",
)


def _thinking_disabled_extra(model_name: str) -> dict[str, Any]:
    low = model_name.lower()
    if any(marker in low for marker in _THINKING_MODEL_MARKERS):
        return {"chat_template_kwargs": {"enable_thinking": False}}
    return {}


def _extract_message_text(message: dict[str, Any]) -> str:
    content = (message.get("content") or "").strip()
    if content:
        return content
    reasoning = message.get("reasoning") or ""
    return reasoning.strip() if isinstance(reasoning, str) else ""


class LLM(Protocol):
    """Minimal chat interface shared by the live and mock clients."""

    def complete(self, system: str, user: str) -> str: ...


class ChatModel:
    """HTTP client for OpenAI-compatible APIs (Together, Cerebras, Fireworks, local vLLM).

    Uses only the standard library so the package stays dependency-light.
    """

    def __init__(
        self,
        *,
        api_key: str | None,
        base_url: str,
        model_name: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        retry_attempts: int = 2,
        retry_delay: float = 1.0,
    ) -> None:
        if not api_key:
            raise ValueError(
                "API key required for live LLM mode. Set the provider key or use KAVACH_LLM_MODE=mock."
            )
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        # Together-specific chat_template_kwargs; other providers reject extra_body.
        self._extra = (
            _thinking_disabled_extra(model_name)
            if "together.xyz" in self.base_url or "together.ai" in self.base_url
            else {}
        )

    def complete(self, system: str, user: str) -> str:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        body: dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if self._extra:
            body["extra_body"] = self._extra

        last_err: Exception | None = None
        attempts = max(1, self.retry_attempts + 1)
        for attempt in range(1, attempts + 1):
            try:
                payload = self._post_json("/chat/completions", body)
                return _extract_message_text(payload["choices"][0]["message"])
            except Exception as exc:  # noqa: BLE001 - retried then re-raised
                last_err = exc
                if attempt < attempts:
                    time.sleep(self.retry_delay)
        assert last_err is not None
        raise last_err

    def _post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "kavach/0.1",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"API error {exc.code}: {detail}") from exc


class MockChatModel:
    """Deterministic offline LLM for CI: returns structured JSON for agent roles."""

    _CAP_OPEN = "KAVACHCAP["
    _CAP_CLOSE = "]KAVACHEND"

    def __init__(self, model_name: str = "mock") -> None:
        self.model_name = model_name

    def complete(self, system: str, user: str) -> str:
        if "EXPLOITER verification" in system:
            return self._confirm_json(user)
        if "EXPLOITER agent" in system:
            return self._exploiter_json(user)
        if "enumerating concrete HTTP" in system:
            return self._enumerate_json(user)
        if "extract exploitation intelligence" in system:
            return self._web_intel_json(user)
        tag = system.split("\n", 1)[0][:80]
        return (
            "[MOCK LLM OUTPUT]\n"
            f"role_hint: {tag}\n"
            "note: offline deterministic stub; replace with a live model via KAVACH_LLM_MODE=live.\n"
            f"input_chars: {len(user)}"
        )

    def _extract_target(self, user: str) -> str:
        m = re.search(r"Target URL \(AUTHORIZED\):\s*(https?://[^\s]+)", user)
        if m:
            return m.group(1).rstrip("/")
        m = re.search(r"https?://[^\s]+", user)
        return m.group(0).rstrip("/") if m else "http://127.0.0.1"

    def _exploiter_json(self, user: str) -> str:
        target = self._extract_target(user)
        marker = self._CAP_OPEN
        low = user.lower()
        candidates: list[dict[str, Any]] = []
        if "api/ping" in low or "command injection" in low or "/api/ping" in low:
            injection = (
                f'x; printf "{self._CAP_OPEN}%s{self._CAP_CLOSE}" "$KAVACH_FLAG"'
            )
            from urllib.parse import quote

            url = f"{target}/api/ping?host={quote(injection)}"
            candidates.append(
                {
                    "method": "GET",
                    "url": f"{target}/api/ping?host=127.0.0.1",
                    "success_marker": marker,
                }
            )
            candidates.append(
                {
                    "method": "GET",
                    "url": url,
                    "success_marker": marker,
                }
            )
        plan: dict[str, Any] = {
            "reasoning": "mock exploiter plan for offline CI",
            "success_marker": marker,
            "candidates": candidates,
        }
        if candidates:
            plan["url"] = candidates[-1]["url"]
            plan["method"] = "GET"
        return json.dumps(plan)

    def _confirm_json(self, user: str) -> str:
        low = user.lower()
        confirmed = (
            "uid=" in low
            or "root:x:" in low
            or self._CAP_OPEN in user
            or "kavach_flag{" in low
        )
        excerpt = ""
        if self._CAP_OPEN in user:
            m = re.search(
                re.escape(self._CAP_OPEN) + r"(.*?)" + re.escape(self._CAP_CLOSE),
                user,
                re.DOTALL,
            )
            excerpt = m.group(1).strip() if m else self._CAP_OPEN
        elif "uid=" in user:
            m = re.search(r"uid=\d+\([^)]+\)", user)
            excerpt = m.group(0) if m else "uid="
        return json.dumps(
            {
                "confirmed": confirmed,
                "reasoning": "mock confirm pass",
                "proof_type": "rce" if confirmed else "none",
                "proof_excerpt": excerpt,
            }
        )

    def _enumerate_json(self, user: str) -> str:
        base = self._exploiter_json(user)
        data = json.loads(base)
        if len(data.get("candidates") or []) < 8 and data.get("url"):
            data["candidates"] = (data.get("candidates") or []) + [
                dict(c) for c in (data.get("candidates") or [])
            ]
        return json.dumps(
            {
                "reasoning": "mock enumeration pass",
                "candidates": data.get("candidates") or [],
            }
        )

    def _web_intel_json(self, user: str) -> str:
        paths: list[str] = []
        headers: list[dict[str, str]] = []
        for m in re.finditer(r"(/api/[a-zA-Z0-9_./-]+)", user):
            p = m.group(1).split("?")[0]
            if p not in paths:
                paths.append(p)
        if "x-middleware-subrequest" in user.lower():
            headers.append(
                {
                    "name": "x-middleware-subrequest",
                    "value": "middleware:middleware:middleware:middleware:middleware",
                    "note": "from search snippet",
                }
            )
        return json.dumps(
            {
                "summary": "mock web intel extraction",
                "probe_paths": paths[:8],
                "request_headers": headers,
                "techniques": [],
                "success_markers": [],
            }
        )


def make_llm(config: dict[str, Any]) -> LLM:
    """Build the chat client according to config['llm_mode']."""
    from .logging_utils import LoggingLLM

    if config.get("llm_mode", "mock") == "mock":
        inner: LLM = MockChatModel(config.get("model", "mock"))
    else:
        provider = config["provider"]
        api_key = os.environ.get(provider["key_env"])
        inner = ChatModel(
            api_key=api_key,
            base_url=provider["base_url"],
            model_name=config["model"],
            temperature=config["temperature"],
            max_tokens=config["max_tokens"],
        )
    return LoggingLLM(inner, config)
