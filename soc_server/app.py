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
from datetime import timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from perception.review_service import ReviewService
from review_api import create_app
from soc_server.lab import Lab
from soc_server.reader import KnowledgeReader, metrics
from soc_server.runner import LiveRunner

COMPARISON = Path(__file__).resolve().parent.parent / "experiments" / "dedale_results" / "final_host_scores.json"
COMPARISON_RUNS = {"no learning (static)": "static_F_static", "learning behind the gate": "gated_F_gated",
                   "learning without the gate": "ungated_F_ungated",
                   "gate + analyst (4 h)": "gated_analyst_F_d4"}


class SpeedIn(BaseModel):
    speed: float = Field(gt=0, le=86_400)


def comparison(path: Path | None = COMPARISON, run_ids: dict[str, str] | None = None) -> dict:
    """Reviews per day of the dataset's frozen runs (no learning / gate / no gate / analyst), if available."""
    if path is None or not path.exists():
        return {}
    runs = json.loads(path.read_text(encoding="utf-8"))["runs"]
    return {label: {"mean": runs[r]["reviews_per_day"]["mean"], "by_day": runs[r]["reviews_per_day"]["by_day"]}
            for label, r in (run_ids or COMPARISON_RUNS).items() if r in runs}


def build_app(runner: LiveRunner, *, accounts=None, tokens: dict[str, str] | None = None, dataset=None) -> FastAPI:
    """The demo API.  `dataset` (soc_server.datasets.Dataset) names the replay and its frozen comparison runs."""
    app = create_app(runner.cases, tokens, accounts=accounts, clock=runner.now)
    principal, role = app.state.principal, app.state.role
    reader = KnowledgeReader(runner.home / "ks.sqlite")
    service = ReviewService(runner.cases, clock=runner.now)
    app.state.reader = reader

    label = dataset.label if dataset is not None else "DEDALE"
    cmp_path = dataset.comparison if dataset is not None else COMPARISON
    cmp_runs = dataset.comparison_runs if dataset is not None else COMPARISON_RUNS

    @app.get("/live/status")
    def live_status(p=Depends(principal)) -> dict:
        return {**runner.status(), "dataset": label}

    @app.get("/live/activity")
    def live_activity(hours: int = Query(24, ge=1, le=24 * 31), p=Depends(principal)) -> dict:
        """Cases opened per stream hour, closed automatically vs sent to an analyst (the last `hours`)."""
        end = runner.now()
        start = (end - timedelta(hours=hours - 1)).replace(minute=0, second=0, microsecond=0)
        counts = runner.cases.opened_per_hour(start)
        out, t = [], start
        while t <= end:
            key = t.strftime("%Y-%m-%dT%H")
            out.append({"hour": t.isoformat(), "closed_automatically": counts.get((key, False), 0),
                        "sent_to_analyst": counts.get((key, True), 0)})
            t += timedelta(hours=1)
        return {"hours": out}

    @app.get("/hosts/{host}/timeline")
    def host_timeline(host: str, limit: int = Query(500, ge=1, le=5000), p=Depends(principal)) -> dict:
        """Every case on a host, oldest first (the host's story as the SOC saw it)."""
        return service.host_timeline(host, limit)

    lab = Lab()

    def _lab(call):
        try:
            return call()
        except KeyError as e:
            raise HTTPException(404, f"unknown {e.args[0]!r}") from None
        except FileNotFoundError as e:
            raise HTTPException(503, f"recorded results missing: {e}") from None

    @app.get("/lab/runs")
    def lab_runs(p=Depends(principal)) -> list[dict]:
        """The Contamination Lab's recorded GUIDE v2 runs (soc_server/lab.py)."""
        return lab.runs()

    @app.get("/lab/{run}/summary")
    def lab_summary(run: str, p=Depends(principal)) -> dict:
        return _lab(lambda: lab.summary(run))

    @app.get("/lab/{run}/pairs")
    def lab_pairs(run: str, family: str | None = None, change: str | None = None,
                  limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), p=Depends(principal)) -> dict:
        return _lab(lambda: lab.pairs(run, family=family, change=change, limit=limit, offset=offset))

    @app.get("/lab/{run}/pairs/{pair_id}")
    def lab_pair(run: str, pair_id: str, p=Depends(principal)) -> dict:
        return _lab(lambda: lab.pair(run, pair_id))

    @app.get("/techniques")
    def techniques(p=Depends(principal)) -> dict:
        """ATT&CK techniques the pipeline reasons about: {id: {name, detail}} (from SSE's table)."""
        from perception.sse import TECHNIQUE_TABLE
        out = {}
        for tid, c in TECHNIQUE_TABLE.items():
            name, _, detail = c.description.partition(" — ")
            out[tid] = {"name": name.strip(), "detail": detail.strip()}
        return out

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

    @app.get("/knowledge/hostnames")
    def ks_hostnames(p=Depends(principal)) -> list[str]:
        """The hosts in the store (its inventory): for host pickers."""
        return reader.hosts()

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
        return {**metrics(runner.cases, reader), "comparison": comparison(cmp_path, cmp_runs)}

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
