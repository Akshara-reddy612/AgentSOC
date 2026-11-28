"""
experiments/memstream_loop.py

Checklist A7 (2026-11-28; design experiments/A7_MEMSTREAM_DESIGN.md): the SOC loop with MemStream deciding which
test-period host events alert, instead of "the store has not learned this key".  Experiment code only: the pipeline
modules are unchanged; this subclass replaces only the novelty test of `SocLoop.process_host_event`.

  - mode "static": the store learns nothing, so MemStream is the only memory (triage closes an alert whose key the
    store learned as routine, which would otherwise mix the keyed store into the baseline);
  - mode "frozen": the store keeps the training weeks' keys, so a review needs a novel key AND a MemStream anomaly
    (the combination, design stage 4).

Scores are read in stream order from a score file of experiments/memstream_eval.py, written for the same events in
the same order (the replay's iterator, plants merged by time); every lookup checks host, channel and record id.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import numpy as np

from experiments.memstream import detector_keys
from perception.host_detection import host_alert, malformed_host_event, novel_keys
from perception.soc_loop import SocLoop

CHANNELS = {"sysmon": 0, "security": 1, "powershell": 2}


class ScoreStream:
    """The scores of one score file, consumed in order."""

    def __init__(self, npz: Path, hosts: list[str]) -> None:
        z = np.load(npz)
        self.host, self.ch, self.rid = z["host"], z["ch"], z["rid"]
        self.t, self.score = z["t"], z["score"]
        self.host_ix = {h: i for i, h in enumerate(hosts)}
        self.i = 0

    def skip_until(self, ts: float) -> None:
        while self.i < len(self.t) and self.t[self.i] < ts:
            self.i += 1

    def next(self, event: dict) -> float:
        i = self.i
        if i >= len(self.score):
            raise RuntimeError("score file ended before the replay")
        if (self.host[i] != self.host_ix.get(event["host"], -1) or self.ch[i] != CHANNELS.get(event["ch"], 3)
                or self.rid[i] != int(event["rid"])):
            raise RuntimeError(f"score file out of step with the replay at record {i}: "
                               f"{event['host']} {event['ch']} {event['rid']}")
        self.i += 1
        return float(self.score[i])


class MemStreamLoop(SocLoop):
    def __init__(self, *args, scores: ScoreStream, tau: float, **kw) -> None:
        super().__init__(*args, **kw)
        self.scores = scores
        self.tau = tau
        self._started = False

    def process_host_event(self, event: dict, at: datetime) -> None:
        if at < self.training_end:                         # training weeks: exactly the base loop
            super().process_host_event(event, at)
            return
        self._advance(at)                                  # ends training at the first test-period event
        if malformed_host_event(event):
            super().process_host_event(event, at)          # refused and counted exactly as the base loop does
            return
        if not self._started:
            self.scores.skip_until(self.training_end.timestamp())
            self._started = True
        self.counts["events_test"] += 1
        self.monitor.observe({"source_host": event["host"], "target_host": event["host"],
                              "source_user": event.get("user")}, at)
        keys = detector_keys(event)
        keys = [(n, k) for n, k in keys if n in self.detectors]
        if not keys:
            return
        if self.scores.next(event) <= self.tau:
            self.counts["memstream_normal"] += 1
            return
        self.counts["memstream_anomalous"] += 1
        if self.mode == "frozen":                          # combination: only keys the store has not learned
            keys = novel_keys(self.db, event, self.detectors)
        for name, key in keys:
            self._handle_alert(host_alert(event, name, key, self.db), at)
