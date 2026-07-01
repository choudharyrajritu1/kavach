from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator

from .schemas import PipelineState

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    cve_id      TEXT NOT NULL,
    stage       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    state_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_cve ON runs (cve_id);
CREATE INDEX IF NOT EXISTS idx_runs_stage ON runs (stage);
"""


class RunStore:
    """Lightweight persistence layer for pipeline runs.

    SQLite by default (zero-config, file-backed). The same interface maps
    cleanly onto PostgreSQL for production deployments.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    def save(self, state: PipelineState) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO runs (run_id, cve_id, stage, created_at, updated_at, state_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    stage=excluded.stage,
                    updated_at=excluded.updated_at,
                    state_json=excluded.state_json
                """,
                (
                    state.run_id,
                    state.cve_id,
                    state.stage,
                    state.created_at,
                    state.updated_at,
                    json.dumps(state.to_dict()),
                ),
            )

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT state_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        return json.loads(row["state_json"]) if row else None

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT run_id, cve_id, stage, created_at, updated_at
                FROM runs ORDER BY created_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
