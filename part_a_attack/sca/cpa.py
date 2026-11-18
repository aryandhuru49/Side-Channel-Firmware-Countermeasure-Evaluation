"""Correlation Power Analysis against the first-round AES S-box output.

Leakage model: Hamming weight of SBOX[pt_b XOR k_b] (Brier, Clavier, Olivier,
CHES 2004). Correlations are computed from running sums so that a single pass
over the traces yields the attack result at every checkpoint, which is what the
traces-to-disclosure analysis needs.
"""
from __future__ import annotations

import numpy as np

from .aes import HW, SBOX

GUESSES = np.arange(256, dtype=np.uint8)


def hypotheses(pts: np.ndarray, bytes_: list[int]) -> np.ndarray:
    """(N, len(bytes_)*256) matrix of predicted leakage."""
    cols = [HW[SBOX[pts[:, b, None] ^ GUESSES[None, :]]] for b in bytes_]
    return np.concatenate(cols, axis=1).astype(np.float64)


class RunningCPA:
    """Accumulates the sums needed for Pearson correlation of every guess with every sample."""

    def __init__(self, n_samples: int, bytes_: list[int]):
        self.bytes_ = list(bytes_)
        g = 256 * len(self.bytes_)
        self.n = 0
        self.st = np.zeros(n_samples)
        self.stt = np.zeros(n_samples)
        self.sh = np.zeros(g)
        self.shh = np.zeros(g)
        self.sht = np.zeros((g, n_samples))

    def update(self, traces: np.ndarray, pts: np.ndarray) -> None:
        h = hypotheses(pts, self.bytes_)
        t = np.asarray(traces, dtype=np.float64)
        self.n += len(t)
        self.st += t.sum(0)
        self.stt += (t * t).sum(0)
        self.sh += h.sum(0)
        self.shh += (h * h).sum(0)
        self.sht += h.T @ t

    def correlation(self) -> np.ndarray:
        """(n_bytes, 256, n_samples) correlation coefficients."""
        n = self.n
        num = n * self.sht - np.outer(self.sh, self.st)
        var_h = n * self.shh - self.sh ** 2
        var_t = n * self.stt - self.st ** 2
        den = np.sqrt(np.outer(np.maximum(var_h, 1e-12), np.maximum(var_t, 1e-12)))
        return (num / den).reshape(len(self.bytes_), 256, -1)


def cpa(traces: np.ndarray, pts: np.ndarray, bytes_=range(16)) -> np.ndarray:
    """Full CPA. Returns correlation array (n_bytes, 256, n_samples)."""
    r = RunningCPA(traces.shape[1], list(bytes_))
    r.update(traces, pts)
    return r.correlation()


def progressive_scores(traces, pts, checkpoints, bytes_=range(16), order=None):
    """Peak |rho| per guess at each checkpoint.

    Returns (scores, peak_idx): scores is (n_checkpoints, n_bytes, 256),
    peak_idx is the sample index of the peak for each guess.
    """
    order = np.arange(len(traces)) if order is None else order
    r = RunningCPA(traces.shape[1], list(bytes_))
    scores, peaks, done = [], [], 0
    for c in checkpoints:
        idx = order[done:c]
        if len(idx):
            r.update(traces[idx], pts[idx])
        done = c
        a = np.abs(r.correlation())
        scores.append(a.max(-1))
        peaks.append(a.argmax(-1))
    return np.array(scores), np.array(peaks)


def best_key(scores_last: np.ndarray) -> np.ndarray:
    return scores_last.argmax(-1).astype(np.uint8)


def ranks(scores: np.ndarray, key: np.ndarray) -> np.ndarray:
    """Rank (0 = best) of the correct key byte. scores (..., n_bytes, 256)."""
    correct = np.take_along_axis(scores, key[None, :, None].astype(int).repeat(
        scores.shape[0], 0) if scores.ndim == 3 else key[:, None].astype(int), -1)
    return (scores > correct).sum(-1)
