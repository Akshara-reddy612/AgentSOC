"""
perception/knowledge_db.py

Persistent Knowledge Store (design step S2, 2026-10-11; see
experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md).

A SQLite file holding the Knowledge Store graph (nodes and edges with their
KnowledgeFact attributes, including version history), the environment profile
and an append-only audit log of every write.  The NetworkX graph that SSE,
RSEM, the baseline rule and the guardrails read is a projection of the store:
it is loaded when the store is opened and every write updates it in the same
step (write-through), so the pipeline modules need no change.

Design rules (invariant I6 of the design):
  - Every write goes through KnowledgeDB and is recorded in ks_log in the same
    transaction.  ks_log is append-only (SQLite triggers reject UPDATE and
    DELETE) and complete: replaying it rebuilds the graph as it was after any
    entry (replay_log), which is how a store state is reconstructed or rolled back.
  - Every write names its writer, its event time and its provenance
    (learned_from).  What a writer may write -- trusted fields only, and the
    learning gate -- is decided by the updater (design step S5), not here.
  - Attribute values are stored as typed JSON: KnowledgeFact, the graph's enums,
    datetimes and tuples round-trip exactly.
  - A new version of a KnowledgeFact keeps the earlier versions in
    audit_history (flat list, oldest first).
"""
from __future__ import annotations

import dataclasses
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

import networkx as nx

from perception.environment import GRAPH_ATTR, EnvironmentProfile, profile_of
from perception.knowledge_graph import AccessLevel, AccountType, HostClass, KnowledgeStoreGraph
from perception.knowledge_store import KnowledgeFact
from perception.source_systems import SourceSystem

SCHEMA_VERSION = 1

# Provenance of a stored node or edge (design invariant I3):
#   config        - environment profile / CMDB / synthetic seed data
#   telemetry     - observed to exist in trusted telemetry (says nothing about "normal")
#   training      - learned as normal during the training window
#   closed_benign - learned as normal from a case closed as benign after the gate delay
#   analyst       - entered or confirmed by an analyst
LEARNED_FROM = frozenset({"config", "telemetry", "training", "closed_benign", "analyst"})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ks_log (
    seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    writer  TEXT NOT NULL,
    op      TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS ks_log_no_update BEFORE UPDATE ON ks_log
    BEGIN SELECT RAISE(ABORT, 'ks_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ks_log_no_delete BEFORE DELETE ON ks_log
    BEGIN SELECT RAISE(ABORT, 'ks_log is append-only'); END;
CREATE TABLE IF NOT EXISTS nodes (
    node_id      TEXT PRIMARY KEY,
    node_type    TEXT NOT NULL,
    attrs        TEXT NOT NULL,
    learned_from TEXT NOT NULL,
    created_seq  INTEGER NOT NULL,
    updated_seq  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS edges (
    src          TEXT NOT NULL,
    dst          TEXT NOT NULL,
    key          TEXT NOT NULL,
    edge_type    TEXT NOT NULL,
    attrs        TEXT NOT NULL,
    learned_from TEXT NOT NULL,
    created_seq  INTEGER NOT NULL,
    updated_seq  INTEGER NOT NULL,
    PRIMARY KEY (src, dst, key)
);
"""

# ---------------------------------------------------------------------------
# Typed JSON
# ---------------------------------------------------------------------------

_ENUM_TYPES: dict[str, type[Enum]] = {t.__name__: t for t in (HostClass, AccountType, AccessLevel, SourceSystem)}
_TAGS = ("__fact__", "__enum__", "__dt__", "__tuple__")


def encode_value(v: Any) -> Any:
    """Python value -> JSON-compatible value that decode_value turns back into an equal value."""
    if isinstance(v, Enum):             # before int: AccessLevel is an IntEnum
        if _ENUM_TYPES.get(type(v).__name__) is not type(v):
            raise TypeError(f"enum type {type(v)!r} is not registered for storage")
        return {"__enum__": type(v).__name__, "value": v.value}
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, KnowledgeFact):
        return {"__fact__": {
            "value": encode_value(v.value), "version": v.version, "confidence": v.confidence,
            "source": v.source.value, "timestamp": v.timestamp.isoformat(),
            "audit_history": [encode_value(h) for h in v.audit_history],
        }}
    if isinstance(v, datetime):
        return {"__dt__": v.isoformat()}
    if isinstance(v, tuple):
        return {"__tuple__": [encode_value(x) for x in v]}
    if isinstance(v, list):
        return [encode_value(x) for x in v]
    if isinstance(v, dict):
        if not all(isinstance(k, str) for k in v) or any(k in _TAGS for k in v):
            raise TypeError("stored dicts need string keys that are not storage tags")
        return {k: encode_value(x) for k, x in v.items()}
    raise TypeError(f"cannot store a value of type {type(v).__name__}")


def decode_value(v: Any) -> Any:
    if isinstance(v, list):
        return [decode_value(x) for x in v]
    if not isinstance(v, dict):
        return v
    if len(v) == 1 and "__fact__" in v:
        f = v["__fact__"]
        return KnowledgeFact(value=decode_value(f["value"]), version=f["version"], confidence=f["confidence"],
                             source=SourceSystem(f["source"]), timestamp=datetime.fromisoformat(f["timestamp"]),
                             audit_history=[decode_value(h) for h in f["audit_history"]])
    if len(v) == 2 and "__enum__" in v:
        return _ENUM_TYPES[v["__enum__"]](v["value"])
    if len(v) == 1 and "__dt__" in v:
        return datetime.fromisoformat(v["__dt__"])
    if len(v) == 1 and "__tuple__" in v:
        return tuple(decode_value(x) for x in v["__tuple__"])
    return {k: decode_value(x) for k, x in v.items()}


def _dumps(v: Any) -> str:
    return json.dumps(encode_value(v), sort_keys=True, separators=(",", ":"))


def _loads(s: str) -> Any:
    return decode_value(json.loads(s))


def _stored_copy(v: Any) -> Any:
    """The value exactly as the store holds it (a deep copy, so callers cannot change the projection)."""
    return decode_value(encode_value(v))


def graph_signature(g: nx.MultiDiGraph) -> tuple:
    """Exact, order-independent content of a graph (nodes, edges, attributes), for comparisons."""
    nodes = sorted((n, _dumps(dict(d))) for n, d in g.nodes(data=True))
    edges = sorted((u, v, _dumps(k), _dumps(dict(d))) for u, v, k, d in g.edges(keys=True, data=True))
    return tuple(nodes), tuple(edges)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class KnowledgeDB:
    """SQLite-backed Knowledge Store with a live graph projection (see module docstring)."""

    def __init__(self, path: str | Path, profile: EnvironmentProfile | None = None, *,
                 created_at: datetime | None = None) -> None:
        """
        Open the store at `path`, creating it if it does not exist.  A new store
        needs the environment `profile`; `created_at` is the time recorded for
        that first entry (default: now; a replay passes its start time so the
        store is deterministic).  An existing store keeps its own profile.
        """
        self.path = str(path)
        self._con = sqlite3.connect(self.path, isolation_level=None)   # autocommit; batch() groups writes
        if self.path != ":memory:":
            self._con.execute("PRAGMA journal_mode=WAL")
            self._con.execute("PRAGMA synchronous=NORMAL")
        self._con.executescript(_SCHEMA)
        self._in_batch = False
        self._graph = nx.MultiDiGraph()
        stored = self._meta("profile")
        if stored is None:
            if profile is None:
                raise ValueError("a new Knowledge Store needs an environment profile")
            self._profile = profile
            with self.batch():
                self._con.execute("INSERT INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
                self._con.execute("INSERT INTO meta VALUES ('profile', ?)", (json.dumps(profile.to_dict()),))
                self._log("system", created_at or datetime.now(timezone.utc), "set_profile", profile.to_dict())
        else:
            if self._meta("schema_version") != str(SCHEMA_VERSION):
                raise ValueError(f"store schema {self._meta('schema_version')!r}, code expects {SCHEMA_VERSION}")
            self._profile = EnvironmentProfile.from_dict(json.loads(stored))
            if profile is not None and profile.to_dict() != self._profile.to_dict():
                raise ValueError("this store was created for a different environment profile")
        self._reload_projection()
        self._kg = KnowledgeStoreGraph.from_graph(self._graph)

    # -- reading ------------------------------------------------------------

    @property
    def graph(self) -> KnowledgeStoreGraph:
        """The live projection the pipeline reads (SSE, RSEM, baseline, guardrails)."""
        return self._kg

    @property
    def profile(self) -> EnvironmentProfile:
        return self._profile

    def learned_from(self, node_id: str) -> str | None:
        row = self._con.execute("SELECT learned_from FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
        return row[0] if row else None

    def edge_learned_from(self, src: str, dst: str, key: Any) -> str | None:
        row = self._con.execute("SELECT learned_from FROM edges WHERE src = ? AND dst = ? AND key = ?",
                                (src, dst, _dumps(key))).fetchone()
        return row[0] if row else None

    def audit_log(self, since_seq: int = 0) -> Iterator[dict]:
        for seq, ts, writer, op, payload in self._con.execute(
                "SELECT seq, ts, writer, op, payload FROM ks_log WHERE seq > ? ORDER BY seq", (since_seq,)):
            yield {"seq": seq, "ts": ts, "writer": writer, "op": op, "payload": json.loads(payload)}

    def last_seq(self) -> int:
        return self._con.execute("SELECT COALESCE(MAX(seq), 0) FROM ks_log").fetchone()[0]

    def projection_matches_store(self) -> bool:
        """False if something changed the in-memory graph without going through the store."""
        fresh = nx.MultiDiGraph()
        self._fill_from_tables(fresh)
        return graph_signature(fresh) == graph_signature(self._graph)

    def replay_log(self, upto_seq: int | None = None) -> nx.MultiDiGraph:
        """Rebuild the graph from the audit log alone, as it was after entry `upto_seq` (default: now)."""
        g = nx.MultiDiGraph()
        g.graph[GRAPH_ATTR] = self._profile
        for entry in self.audit_log():
            if upto_seq is not None and entry["seq"] > upto_seq:
                break
            p, op = entry["payload"], entry["op"]
            if op == "add_node":
                g.add_node(p["node_id"], **decode_value(p["attrs"]))
            elif op == "add_edge":
                g.add_edge(p["src"], p["dst"], key=decode_value(p["key"]), **decode_value(p["attrs"]))
            elif op == "set_fact":
                g.nodes[p["node_id"]][p["name"]] = decode_value(p["fact"])
        return g

    # -- writing ------------------------------------------------------------

    @contextmanager
    def batch(self) -> Iterator[None]:
        """Group writes into one transaction; on error everything in it is undone, projection included."""
        if self._in_batch:
            yield
            return
        self._con.execute("BEGIN")
        self._in_batch = True
        try:
            yield
        except BaseException:
            self._con.execute("ROLLBACK")
            self._in_batch = False
            self._reload_projection()
            raise
        self._con.execute("COMMIT")
        self._in_batch = False

    def add_node(self, node_id: str, attrs: dict, *, writer: str, at: datetime, learned_from: str) -> None:
        with self.batch():
            self._add_node(node_id, attrs, writer, at, learned_from)

    def add_edge(self, src: str, dst: str, key: Any, attrs: dict, *, writer: str, at: datetime,
                 learned_from: str) -> None:
        with self.batch():
            self._add_edge(src, dst, key, attrs, writer, at, learned_from)

    def set_fact(self, node_id: str, name: str, value: Any, *, confidence: float, source: SourceSystem,
                 writer: str, at: datetime) -> KnowledgeFact:
        """Record a new version of a node's KnowledgeFact attribute (version 1 if it has none)."""
        with self.batch():
            if node_id not in self._graph:
                raise KeyError(f"unknown node {node_id!r}")
            old = self._graph.nodes[node_id].get(name)
            if old is not None and not isinstance(old, KnowledgeFact):
                raise TypeError(f"{node_id}.{name} is not a KnowledgeFact attribute")
            fact = KnowledgeFact(
                value=value, version=old.version + 1 if old else 1, confidence=confidence, source=source,
                timestamp=at,
                audit_history=[*old.audit_history, dataclasses.replace(old, audit_history=[])] if old else [])
            seq = self._log(writer, at, "set_fact", {"node_id": node_id, "name": name, "fact": encode_value(fact)})
            attrs = dict(self._graph.nodes[node_id])
            attrs[name] = fact
            self._con.execute("UPDATE nodes SET attrs = ?, updated_seq = ? WHERE node_id = ?",
                              (_dumps(attrs), seq, node_id))
            self._graph.nodes[node_id][name] = _stored_copy(fact)
            return fact

    def import_graph(self, source: KnowledgeStoreGraph | nx.MultiDiGraph, *, writer: str, at: datetime,
                     learned_from: str = "config") -> None:
        """Write every node and edge of a graph built for the same environment profile (one transaction)."""
        g = source.graph if isinstance(source, KnowledgeStoreGraph) else source
        if profile_of(g).to_dict() != self._profile.to_dict():
            raise ValueError("graph was built for a different environment profile")
        with self.batch():
            for node_id, attrs in g.nodes(data=True):
                self._add_node(node_id, dict(attrs), writer, at, learned_from)
            for src, dst, key, attrs in g.edges(keys=True, data=True):
                self._add_edge(src, dst, key, dict(attrs), writer, at, learned_from)

    def close(self) -> None:
        self._con.close()

    def __enter__(self) -> "KnowledgeDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- internals ------------------------------------------------------------

    def _meta(self, key: str) -> str | None:
        row = self._con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def _log(self, writer: str, at: datetime, op: str, payload: dict) -> int:
        if not writer:
            raise ValueError("every write names its writer")
        if at.tzinfo is None:
            raise ValueError("event time must be timezone-aware")
        cur = self._con.execute("INSERT INTO ks_log (ts, writer, op, payload) VALUES (?, ?, ?, ?)",
                                (at.isoformat(), writer, op, json.dumps(payload, sort_keys=True)))
        return cur.lastrowid

    def _add_node(self, node_id: str, attrs: dict, writer: str, at: datetime, learned_from: str) -> None:
        if not isinstance(node_id, str):
            raise TypeError("node ids are strings")
        if learned_from not in LEARNED_FROM:
            raise ValueError(f"learned_from must be one of {sorted(LEARNED_FROM)}")
        if not isinstance(attrs.get("node_type"), str):
            raise ValueError("a node needs a node_type")
        if node_id in self._graph:
            raise ValueError(f"node {node_id!r} already exists")
        seq = self._log(writer, at, "add_node",
                        {"node_id": node_id, "attrs": encode_value(attrs), "learned_from": learned_from})
        self._con.execute("INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?)",
                          (node_id, attrs["node_type"], _dumps(attrs), learned_from, seq, seq))
        self._graph.add_node(node_id, **_stored_copy(attrs))

    def _add_edge(self, src: str, dst: str, key: Any, attrs: dict, writer: str, at: datetime,
                  learned_from: str) -> None:
        if learned_from not in LEARNED_FROM:
            raise ValueError(f"learned_from must be one of {sorted(LEARNED_FROM)}")
        if not isinstance(attrs.get("edge_type"), str):
            raise ValueError("an edge needs an edge_type")
        if src not in self._graph or dst not in self._graph:
            raise KeyError(f"edge endpoints must exist: {src!r} -> {dst!r}")
        if self._graph.has_edge(src, dst, key):
            raise ValueError(f"edge {src!r} -[{key!r}]-> {dst!r} already exists")
        seq = self._log(writer, at, "add_edge", {"src": src, "dst": dst, "key": encode_value(key),
                                                 "attrs": encode_value(attrs), "learned_from": learned_from})
        self._con.execute("INSERT INTO edges VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                          (src, dst, _dumps(key), attrs["edge_type"], _dumps(attrs), learned_from, seq, seq))
        self._graph.add_edge(src, dst, key=key, **_stored_copy(attrs))

    def _fill_from_tables(self, g: nx.MultiDiGraph) -> None:
        g.graph[GRAPH_ATTR] = self._profile
        for node_id, attrs in self._con.execute("SELECT node_id, attrs FROM nodes ORDER BY created_seq"):
            g.add_node(node_id, **_loads(attrs))
        for src, dst, key, attrs in self._con.execute("SELECT src, dst, key, attrs FROM edges ORDER BY created_seq"):
            g.add_edge(src, dst, key=_loads(key), **_loads(attrs))

    def _reload_projection(self) -> None:
        """Make the in-memory graph equal to the committed tables again (same object, so readers stay valid)."""
        self._graph.clear()
        self._fill_from_tables(self._graph)
