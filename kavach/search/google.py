"""Google search via SerpAPI (https://serpapi.com/)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import serpapi


@dataclass
class OrganicResult:
    position: int | None
    title: str
    link: str
    snippet: str
    displayed_link: str = ""

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> OrganicResult:
        return cls(
            position=raw.get("position"),
            title=str(raw.get("title") or ""),
            link=str(raw.get("link") or ""),
            snippet=str(raw.get("snippet") or ""),
            displayed_link=str(raw.get("displayed_link") or ""),
        )


@dataclass
class SearchResults:
    query: str
    organic_results: list[OrganicResult] = field(default_factory=list)
    total_results: str = ""
    search_metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def as_text(self, *, max_results: int = 10) -> str:
        lines = [f"Query: {self.query}", f"Total: {self.total_results or 'unknown'}"]
        for r in self.organic_results[:max_results]:
            lines.append(f"{r.position or '-'}. {r.title}")
            lines.append(f"   {r.link}")
            if r.snippet:
                lines.append(f"   {r.snippet}")
        return "\n".join(lines)


class GoogleSearchClient:
    """Thin wrapper around serpapi.Client for Google organic search."""

    def __init__(self, api_key: str | None = None) -> None:
        key = api_key or os.getenv("SERPAPI_API_KEY", "")
        if not key:
            raise ValueError(
                "SerpAPI key missing. Set SERPAPI_API_KEY in .env or pass api_key=."
            )
        self._client = serpapi.Client(api_key=key)

    def search(
        self,
        query: str,
        *,
        location: str = "",
        hl: str = "en",
        gl: str = "us",
        google_domain: str = "google.com",
        start: int = 0,
        num: int = 10,
        safe: str = "active",
        extra: dict[str, Any] | None = None,
    ) -> SearchResults:
        """Run a Google search and return parsed organic results."""
        params: dict[str, Any] = {
            "engine": "google",
            "q": query,
            "hl": hl,
            "gl": gl,
            "google_domain": google_domain,
            "start": str(start),
            "num": str(num),
            "safe": safe,
        }
        if location:
            params["location"] = location
        if extra:
            params.update(extra)

        raw = self._client.search(params)
        organic = [
            OrganicResult.from_raw(item)
            for item in (raw.get("organic_results") or [])
            if isinstance(item, dict)
        ]
        search_info = raw.get("search_information") or {}
        return SearchResults(
            query=query,
            organic_results=organic,
            total_results=str(search_info.get("total_results") or ""),
            search_metadata=dict(raw.get("search_metadata") or {}),
            raw=raw,
        )

    def search_cve(self, cve_id: str, *, extra_terms: str = "") -> SearchResults:
        """Search Google for public CVE intelligence (advisory, PoC, patch)."""
        q = f"{cve_id} vulnerability exploit advisory patch"
        if extra_terms:
            q = f"{cve_id} {extra_terms}"
        return self.search(q, num=10)
