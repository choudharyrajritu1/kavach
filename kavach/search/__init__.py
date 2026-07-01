"""External search integrations (Google via SerpAPI, etc.)."""

from .google import GoogleSearchClient, OrganicResult, SearchResults
from .intel import WebIntel, enrich_state_from_web_search, gather_web_intel

__all__ = [
    "GoogleSearchClient",
    "OrganicResult",
    "SearchResults",
    "WebIntel",
    "enrich_state_from_web_search",
    "gather_web_intel",
]
