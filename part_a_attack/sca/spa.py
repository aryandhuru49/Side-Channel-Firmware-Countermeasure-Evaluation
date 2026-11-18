"""Simple power analysis of the SCA101 Lab 2.1B password check.

Target firmware (chipwhisperer/firmware/mcu/basic-passwdcheck/basic-passwdcheck.c)
compares the guess byte by byte and ``break``s on the first mismatch, so the
time spent in the loop grows with the number of correct leading characters.

The recorded data set only contains traces for the prefixes NewAE actually
captured. ``RecordedPasswordTarget`` replays those recordings with the same
selection rule NewAE's simulator uses, so the attack code below sees the
device only through ``query(guess) -> trace``. The secret never leaves the
target object; the attacker does not read it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"


class RecordedPasswordTarget:
    """Replays recorded traces as if querying the device (one trace per query)."""

    def __init__(self, recordings: dict, secret_len: int = 5, seed: int = 0):
        self._rec = {k: np.asarray(v) for k, v in recordings.items() if k != "N_each"}
        # The secret is implied by which full-length key is not all spaces after the
        # longest prefix; we derive it once so query() can apply NewAE's rule.
        self._secret = max((k for k in self._rec if " " not in k), key=len)
        self._len = secret_len
        self._rng = np.random.default_rng(seed)
        self.queries = 0

    def query(self, guess: str) -> np.ndarray:
        if len(guess) > self._len:
            raise ValueError("only guesses up to 5 characters were recorded")
        recorded = ""
        for i, ch in enumerate(guess):
            if self._secret[i] != ch:
                recorded += " " * (len(guess) - i)
                break
            recorded += ch
        self.queries += 1
        traces = self._rec[recorded]
        return traces[self._rng.integers(len(traces))]

    def check(self, guess: str) -> bool:
        """The device's accept/reject answer (what a user would see on the UART)."""
        return guess == self._secret


@dataclass
class PositionResult:
    position: int
    best_char: str
    scores: dict[str, float]
    divergence_sample: int
    margin: float  # best score / second best score


@dataclass
class SpaResult:
    recovered: str
    positions: list[PositionResult] = field(default_factory=list)
    queries: int = 0


def _outlier_scores(traces: np.ndarray) -> np.ndarray:
    """Sum of absolute difference of each trace from the per-sample median.

    All wrong guesses at a position execute the same instruction path, so their
    traces agree with the median; the correct guess runs one more loop
    iteration and stands out.
    """
    med = np.median(traces, axis=0)
    return np.abs(traces - med).sum(axis=1)


def first_divergence(a: np.ndarray, b: np.ndarray, thresh: float = 0.05) -> int:
    idx = np.flatnonzero(np.abs(a - b) > thresh)
    return int(idx[0]) if idx.size else -1


def attack(target: RecordedPasswordTarget, length: int = 5, charset: str = CHARSET) -> SpaResult:
    """Recover the password one character at a time using one trace per guess."""
    known = ""
    res = SpaResult(recovered="")
    for pos in range(length):
        guesses = [known + c for c in charset]
        traces = np.stack([target.query(g) for g in guesses])
        scores = _outlier_scores(traces)
        order = np.argsort(scores)[::-1]
        best, second = order[0], order[1]
        known += charset[best]
        wrong_med = np.median(np.delete(traces, best, axis=0), axis=0)
        res.positions.append(PositionResult(
            position=pos,
            best_char=charset[best],
            scores=dict(zip(charset, map(float, scores))),
            divergence_sample=first_divergence(traces[best], wrong_med),
            margin=float(scores[best] / scores[second]),
        ))
    res.recovered = known
    res.queries = target.queries
    return res
