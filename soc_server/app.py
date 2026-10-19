"""
soc_server/app.py

The demo server's HTTP API (M4.3): the review API (review_api.create_app,
accounts, analysts' actions stamped with the stream's clock), plus

  /live/status, /live/start, /live/pause, /live/speed   replay control (lead / admin to change)
  /cases/{id}/trace                                      the pipeline, stage by stage
  /knowledge/summary, /knowledge/hosts/{host},
  /knowledge/graph/{host}, /knowledge/retractions,
  /knowledge/audit                                       the Knowledge Store, read-only
  /metrics                                               per-day cases, verdicts, actions, learning;
                                                         frozen comparison runs (RESULTS.md files)
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import Depends, FastAPI, Query
from pydantic import BaseModel, Field

from perception.review_service import ReviewService
from review_api import create_app
from soc_server.reader import KnowledgeReader, metrics
from soc_server.runner import LiveRunner

COMPARISON = Path(__file__).resolve().parent.parent / "experiments" / "dedale_results" / "final_host_scores.json"
COMPARISON_RUNS = {"no learning (static)": "static_F_static", "learning behind the gate": "gated_F_gated",
                   "learning without the gate": "ungated_F_ungated",
                   "gate + analyst (4 h)": "gated_analyst_F_d4"}


class SpeedIn(BaseModel):
    speed: float = Field(gt=0, le=86_400)


def comparison() -> dict:
    """Reviews per day of the frozen DEDALE runs (no learning / gate / no gate / analyst), if available."""
    if not COMPARISON.exists():
        return {}
    runs = json.loads(COMPARISON.read_text(encoding="utf-8"))["runs"]
    return {label: {"mean": runs[r]["reviews_per_day"]["mean"], "by_day": runs[r]["reviews_per_day"]["by_day"]}
            for label, r in COMPARISON_RUNS.items() if r in runs}


def build_app(runner: LiveRunner, *, accounts=None, tokens: dict[str, str] | None = None) -> FastAPI:
    app = create_app(runner.cases, tokens, accounts=accounts, clock=runner.now)
    principal, role = app.state.principal, app.state.role
    reader = KnowledgeReader(runner.home / "ks.sqlite")
    service = ReviewService(runner.cases, clock=runner.now)
    app.state.reader = reader

    @app.get("/live/status")
    def live_status(p=Depends(principal)) -> dict:
        return runner.status()

    @app.post("/live/start")
    def live_start(p=Depends(role("lead", "admin"))) -> dict:
        runner.start()
        return runner.status()

    @app.post("/live/pause")
    def live_pause(p=Depends(role("lead", "admin"))) -> dict:
        runner.pause()
        return runner.status()

    @app.post("/live/speed")
    def live_speed(body: SpeedIn, p=Depends(role("lead", "admin"))) -> dict:
        runner.set_speed(body.speed)
        return runner.status()

    @app.get("/cases/{case_id}/trace")
    def trace(case_id: str, p=Depends(principal)) -> dict:
        return service.trace(case_id)

    @app.get("/knowledge/summary")
    def ks_summary(p=Depends(principal)) -> dict:
        return reader.summary()

    @app.get("/knowledge/hosts/{host}")
    def ks_host(host: str, limit: int = Query(500, ge=1, le=5000), p=Depends(principal)) -> list[dict]:
        return reader.host_patterns(host, limit)

    @app.get("/knowledge/graph/{host}")
    def ks_graph(host: str, limit: int = Query(300, ge=1, le=2000), p=Depends(principal)) -> dict:
        return reader.neighbourhood(host, limit)

    @app.get("/knowledge/retractions")
    def ks_retractions(limit: int = Query(200, ge=1, le=2000), p=Depends(principal)) -> list[dict]:
        return reader.retractions(limit)

    @app.get("/knowledge/audit")
    def ks_audit(since_seq: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=2000),
                 p=Depends(principal)) -> list[dict]:
        return reader.audit(since_seq, limit)

    @app.get("/metrics")
    def get_metrics(p=Depends(principal)) -> dict:
        return {**metrics(runner.cases, reader), "comparison": comparison()}

    return app


def with_frontend(api_app: FastAPI, dist: Path) -> FastAPI:
    """
    One origin for the demo: the API under /api (as the frontend calls it) and the built
    frontend (frontend/dist) at /, with client-side routes (e.g. /cases/case-20) served index.html.
    """
    from fastapi.responses import FileResponse

    root = FastAPI(title="AgentSOC", docs_url=None, redoc_url=None)
    root.mount("/api", api_app)
    index = dist / "index.html"

    @root.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        target = (dist / path).resolve()
        if path and target.is_file() and dist.resolve() in target.parents:     # no path traversal
            return FileResponse(target)
        return FileResponse(index)

    return root
