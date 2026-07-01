from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..config import get_config
from ..database import RunStore
from ..orchestrator import Orchestrator
from ..safety import validate_cve_id

app = FastAPI(
    title="KAVACH",
    version="0.1.0",
    description="Defensive 5-agent CVE research pipeline (analysis only, no live exploits).",
)

_config = get_config()
_store = RunStore(_config["db_path"])


class AnalyzeRequest(BaseModel):
    cve_id: str
    repo_url: str = ""


class AnalyzeResponse(BaseModel):
    run_id: str
    stage: str
    report: dict[str, Any] | None = None


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "llm_mode": _config["llm_mode"]}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    if not validate_cve_id(req.cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE id format (expected CVE-YYYY-NNNN).")
    # Fresh orchestrator per request keeps state isolated; the store is shared.
    state = Orchestrator(_config).analyze(req.cve_id.upper(), req.repo_url)
    report = state.report.__dict__ if state.report else None
    return AnalyzeResponse(run_id=state.run_id, stage=state.stage, report=report)


@app.get("/api/runs")
def list_runs(limit: int = 50) -> dict[str, Any]:
    return {"runs": _store.list_runs(limit=limit)}


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    state = _store.get(run_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return state
