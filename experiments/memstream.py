"""
experiments/memstream.py

Checklist A7 (2026-11-28; design experiments/A7_MEMSTREAM_DESIGN.md): MemStream (Bhatia et al., "MemStream:
Memory-Based Streaming Anomaly Detection", WWW 2022), written from the paper and checked against the reference code
(github.com/Stream-AD/MemStream, code/memstream-knn.py, Apache-2.0; nothing is copied or downloaded).

  - Denoising autoencoder: encoder Linear(d, 2d) + tanh, decoder Linear(2d, d); trained on the N initial records
    (input + 0.001 * Gaussian noise, MSE, Adam lr 1e-2, 5000 full-batch epochs).  The encoder is fixed afterwards.
  - Normalisation by the mean / std of the raw records in memory, recomputed whenever the memory changes; a feature
    whose std is 0 is set to 0.
  - Score: discounted mean L1 distance from the record's encoding to its K nearest memory encodings
    (weights gamma^0 .. gamma^(K-1); gamma = 0, the default, is the nearest-neighbour distance).
  - Update: a record scoring <= beta replaces the oldest memory slot (FIFO), raw record and encoding.

Features (invariant I1): only the fields the host detectors key on, from each detector's own key (host, parent and
child image, account, logon type, source address, pipe, file type, image reading LSASS, the PowerShell
fingerprint -- never command-line or script text), signed-hashed to `HASH_DIM`, plus hour of day (sin, cos).
"""
from __future__ import annotations

import hashlib
import math
from datetime import datetime

import numpy as np

from perception.host_detection import DETECTORS

HASH_DIM = 64
DIM = HASH_DIM + 2


def _slot(token: str) -> tuple[int, float]:
    h = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(h[:4], "little") % HASH_DIM, (1.0 if h[4] & 1 else -1.0)


_SLOTS: dict[str, tuple[int, float]] = {}


def detector_keys(event: dict) -> list[tuple[str, tuple]]:
    """(detector, key) for every detector that keys this event (the keyed store's own input)."""
    out = []
    for name, d in DETECTORS.items():
        k = d.key(event)
        if k is not None:
            out.append((name, k))
    return out


def features(keys: list[tuple[str, tuple]], at: datetime) -> np.ndarray:
    """The record for one event from its detector keys (see module docstring)."""
    x = np.zeros(DIM, dtype=np.float32)
    for name, key in keys:
        tokens = [f"det={name}", f"host={str(key[0]).lower()}",
                  *(f"{name}.{i}={str(v).lower()}" for i, v in enumerate(key[1:], 1))]
        for tok in tokens:
            s = _SLOTS.get(tok)
            if s is None:
                s = _SLOTS[tok] = _slot(tok)
            x[s[0]] += s[1]
    h = (at.hour + at.minute / 60) / 24 * 2 * math.pi
    x[HASH_DIM], x[HASH_DIM + 1] = math.sin(h), math.cos(h)
    return x


class MemStream:
    def __init__(self, init: np.ndarray, *, beta: float, k: int = 3, gamma: float = 0.0, epochs: int = 5000,
                 lr: float = 1e-2, seed: int = 0) -> None:
        import torch
        self.beta, self.k, self.gamma = beta, k, gamma
        self.n, d = init.shape
        self.mem_data = init.astype(np.float64).copy()
        self._sum = self.mem_data.sum(0)
        self._sumsq = (self.mem_data ** 2).sum(0)
        self._refresh_stats()
        torch.manual_seed(seed)
        enc = torch.nn.Sequential(torch.nn.Linear(d, 2 * d), torch.nn.Tanh())
        dec = torch.nn.Sequential(torch.nn.Linear(2 * d, d))
        opt = torch.optim.Adam([*enc.parameters(), *dec.parameters()], lr=lr)
        x = torch.tensor(self._normalise(self.mem_data), dtype=torch.float32)
        for _ in range(epochs):
            opt.zero_grad()
            loss = torch.nn.functional.mse_loss(dec(enc(x + 0.001 * torch.randn_like(x))), x)
            loss.backward()
            opt.step()
        self.train_loss = float(loss.detach())
        self.w = enc[0].weight.detach().numpy().astype(np.float32)      # (2d, d)
        self.b = enc[0].bias.detach().numpy().astype(np.float32)
        self.memory = np.tanh(self._normalise(self.mem_data).astype(np.float32) @ self.w.T + self.b)
        self._buf = np.empty_like(self.memory)
        self._next = 0
        self.updates = 0
        self._weights = np.array([gamma ** i for i in range(k)], dtype=np.float64) if gamma else None

    def _refresh_stats(self) -> None:
        self.mean = self._sum / self.n
        var = np.maximum((self._sumsq - self.n * self.mean ** 2) / (self.n - 1), 0.0)
        self.std = np.sqrt(var)
        self._ok = self.std > 1e-12

    def _normalise(self, x: np.ndarray) -> np.ndarray:
        return np.where(self._ok, (x - self.mean) / np.where(self._ok, self.std, 1.0), 0.0)

    def encode(self, x: np.ndarray) -> np.ndarray:
        return np.tanh(self.w @ self._normalise(x).astype(np.float32) + self.b)

    def score(self, z: np.ndarray) -> float:
        np.subtract(self.memory, z, out=self._buf)
        np.abs(self._buf, out=self._buf)
        dist = self._buf.sum(1)
        if self._weights is None:
            return float(dist.min())
        near = np.sort(np.partition(dist, self.k - 1)[:self.k]).astype(np.float64)
        return float((near * self._weights).sum() / self._weights.sum())

    def step(self, x: np.ndarray) -> tuple[float, bool]:
        """Score one record against the memory, then update the memory if it scores <= beta."""
        z = self.encode(x)
        s = self.score(z)
        if s <= self.beta:
            i = self._next
            old = self.mem_data[i]
            x64 = x.astype(np.float64)
            self._sum += x64 - old
            self._sumsq += x64 ** 2 - old ** 2
            self.mem_data[i] = x64
            self.memory[i] = z
            self._next = (i + 1) % self.n
            self.updates += 1
            self._refresh_stats()
            return s, True
        return s, False
