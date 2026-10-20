"""
soc_server/reader.py

Read-only views for the demo (M4.3): the Knowledge Store through its own
read-only SQLite connection (the runner keeps the only writing connection,
invariant I6), and metrics from the case store.  Nothing here writes.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from collections import Counter, defaultdict
from pathlib import Path

from perception.case_store import CaseStore
from perception.knowledge_db import decode_value
from perception.knowledge_graph import host_node_id

LEARNED = ("training", "closed_benign", "analyst", "ungated")


def _short(attrs: dict) -> dict:
    """Edge / node attributes as plain JSON for a client (facts flattened to their value)."""
    out = {}
    for k, v in attrs.items():
        if hasattr(v, "value") and hasattr(v, "confidence"):
            v = v.value
        if hasattr(v, "isoformat"):
            v = v.isoformat()
        if isinstance(v, (dict, list, str, int, float, bool)) or v is None:
            out[k] = v
        else:
            out[k] = str(v)
    return out


class KnowledgeReader:
    """Read-only queries on a Knowledge Store file."""

    def __init__(self, path: str | Path) -> None:
        uri = Path(path).resolve().as_uri() + "?mode=ro"
        self._con = sqlite3.connect(uri, uri=True, check_same_thread=False)
        self._lock = threading.Lock()

    def close(self) -> None:
        self._con.close()

    def _q(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._con.execute(sql, args).fetchall()

    def summary(self) -> dict:
        nodes = dict(self._q("SELECT node_type, COUNT(*) FROM nodes GROUP BY node_type"))
        edges = defaultdict(dict)
        for t, lf, n in self._q("SELECT edge_type, learned_from, COUNT(*) FROM edges GROUP BY edge_type, learned_from"):
            edges[t][lf] = n
        ops = dict(self._q("SELECT op, COUNT(*) FROM ks_log GROUP BY op"))
        return {"nodes": nodes, "edges": dict(edges), "log_entries": sum(ops.values()),
                "retractions": ops.get("retract_edge", 0)}

    def hosts(self) -> list[str]:
        """Host names in the store (inventory and observed), natural order (CLIENT2 before CLIENT10)."""
        import re
        names = [n for n, in self._q("SELECT json_extract(attrs, '$.host_id') FROM nodes WHERE node_type = 'HostNode'") if n]
        return sorted(set(names), key=lambda s: [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", s)])

    def host_patterns(self, host: str, limit: int = 500) -> list[dict]:
        """What the store has learned about one host: its detector patterns and logons, with provenance."""
        node, key = host_node_id(host), json.dumps(f"host:{host.lower()}")
        rows = self._q("SELECT e.src, e.dst, e.key, e.edge_type, e.attrs, e.learned_from, l.ts FROM edges e"
                       " JOIN ks_log l ON l.seq = e.created_seq"
                       " WHERE (e.src = ? OR e.dst = ? OR e.key = ?) AND e.learned_from IN (?, ?, ?, ?)"
                       " ORDER BY e.created_seq DESC LIMIT ?", (node, node, key, *LEARNED, limit))
        return [{"src": s, "dst": d, "key": json.loads(k) if k.startswith('"') else k, "type": t,
                 "learned_from": lf, "learned_at": ts, "attrs": _short(decode_value(json.loads(a)))}
                for s, d, k, t, a, lf, ts in rows]

    def retractions(self, limit: int = 200) -> list[dict]:
        rows = self._q("SELECT seq, ts, writer, payload FROM ks_log WHERE op = 'retract_edge' ORDER BY seq DESC LIMIT ?",
                       (limit,))
        return [{"seq": s, "at": ts, "writer": w, **json.loads(p)} for s, ts, w, p in rows]

    def audit(self, since_seq: int = 0, limit: int = 200) -> list[dict]:
        rows = self._q("SELECT seq, ts, writer, op, payload FROM ks_log WHERE seq > ? ORDER BY seq LIMIT ?",
                       (since_seq, limit))
        return [{"seq": s, "at": ts, "writer": w, "op": op, "payload": json.loads(p)} for s, ts, w, op, p in rows]

    def neighbourhood(self, host: str, limit: int = 300) -> dict:
        """Nodes and edges around a host, for a graph view (Cytoscape elements)."""
        edges = self.host_patterns(host, limit)
        nodes = {host_node_id(host): {"id": host_node_id(host), "label": host, "type": "HostNode"}}
        for e in edges:
            for n in (e["src"], e["dst"]):
                nodes.setdefault(n, {"id": n, "label": n.split(":", 1)[-1].rsplit("\\", 1)[-1],
                                     "type": n.split(":", 1)[0]})
        return {"nodes": list(nodes.values()),
                "edges": [{"source": e["src"], "target": e["dst"], "type": e["type"], "key": e["key"],
                           "learned_from": e["learned_from"]} for e in edges]}

    def learned_per_day(self) -> dict[str, dict[str, int]]:
        out: dict[str, Counter] = defaultdict(Counter)
        for lf, ts in self._q("SELECT e.learned_from, l.ts FROM edges e JOIN ks_log l ON l.seq = e.created_seq"
                              " WHERE e.learned_from IN (?, ?, ?, ?)", LEARNED):
            out[ts[:10]][lf] += 1
        for ts, in self._q("SELECT ts FROM ks_log WHERE op = 'retract_edge'"):
            out[ts[:10]]["retracted"] += 1
        return {d: dict(c) for d, c in sorted(out.items())}


def metrics(cases: CaseStore, reader: KnowledgeReader | None = None) -> dict:
    """Per-day cases by outcome, reviews, verdicts, actions; learned / retracted patterns per day."""
    per_day: dict[str, Counter] = defaultdict(Counter)
    verdicts, review = Counter(), Counter()
    for c in cases.cases(limit=10**7):
        per_day[c["opened"][:10]][c["outcome"]] += 1
        review[c["review_status"]] += 1
        if c["verdict"]:
            verdicts[c["verdict"]] += 1
    actions = Counter()
    with cases._lock:
        for status, n in cases._con.execute("SELECT status, COUNT(*) FROM actions GROUP BY status"):
            actions[status] = n
    return {"cases_per_day": {d: dict(c) for d, c in sorted(per_day.items())},
            "review_status": dict(review), "verdicts": dict(verdicts), "actions": dict(actions),
            "learning_per_day": reader.learned_per_day() if reader else {}}
