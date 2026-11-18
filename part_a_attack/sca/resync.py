"""Trace (de)synchronisation utilities.

- ``add_random_delay`` reproduces the SCA201 ADD_JITTER countermeasure in
  software on top of real recorded traces. The firmware inserts
  ``for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);`` before the AES call
  (chipwhisperer/firmware/mcu/simpleserial-aes/simpleserial-aes.c), i.e. a
  data-independent-amount loop of 0..15 iterations that shifts everything after
  the trigger by a random, per-trace offset. We model that as an integer sample
  shift drawn per trace, which is what the oscilloscope records.

- ``resync_sad`` realigns traces by Sum of Absolute Difference, the technique
  taught in SCA201 Lab 1.1A: pick a reference window in one trace, then for each
  trace slide that window over a search range and keep the shift with the
  smallest absolute difference.

Modelling the countermeasure (rather than using NewAE's withdrawn SCA201
captures) keeps Part A reproducible from a single pinned data set while staying
faithful to the firmware. The random delay is applied with a fixed RNG seed so
results are deterministic.
"""
from __future__ import annotations

import numpy as np


def add_random_delay(traces: np.ndarray, pts: np.ndarray, max_iters: int = 15,
                     samples_per_iter: int = 2, trigger: int = 0,
                     residual: float = 0.0, seed: int = 1234
                     ) -> tuple[np.ndarray, np.ndarray]:
    """Shift each trace right by (pt[0] & 0x0F) * samples_per_iter (+ residual).

    The firmware's loop bound is ``*pt & 0x0F`` (the first plaintext byte), so
    the coarse jitter is correlated with data exactly as in the real target.
    ``residual`` adds a small per-trace fractional shift (sample units, applied
    by linear interpolation) modelling the sub-sample timing noise of a real
    volatile delay loop - the part that integer SAD resync cannot remove.
    Returns the jittered traces and the per-trace integer delay in samples.
    """
    rng = np.random.default_rng(seed)
    n, s = traces.shape
    base = (pts[:, 0] & 0x0F).astype(int)
    jitter_noise = rng.integers(0, 2, size=n)
    delays = np.minimum(base + jitter_noise, max_iters) * samples_per_iter
    frac = rng.normal(0, residual, size=n) if residual else np.zeros(n)
    out = np.zeros_like(traces)
    x = np.arange(s)
    for i in range(n):
        shift = delays[i] + frac[i]
        if shift == 0:
            out[i] = traces[i]
        else:
            # sample value at (t - shift): positive shift delays the trace
            out[i] = np.interp(x - shift, x, traces[i], left=traces[i, 0],
                               right=traces[i, -1])
    return out, delays


def add_dispersed_jitter(traces: np.ndarray, pts: np.ndarray, region: tuple[int, int],
                         n_insertions: int = 6, samples_per_iter: int = 2,
                         seed: int = 4321) -> tuple[np.ndarray, np.ndarray]:
    """Model the SCA201 JITTER_2 countermeasure: delays scattered through the rounds.

    The real firmware inserts data-dependent ``volatile`` stalls at several
    points inside SubBytes/ShiftRows (tiny-AES128-C/aes.c, JITTER_2 blocks), so
    the misalignment accumulates differently at each point in the trace. We model
    that by applying several independent small shifts at spread-out offsets
    across ``region``. A single SAD window can realign one point but not all of
    them, which is exactly why this needs more traces (or DTW) to break.

    Returns (jittered_traces, total_delay_at_region_end).
    """
    rng = np.random.default_rng(seed)
    lo, hi = region
    n, s = traces.shape
    out = traces.copy()
    points = np.linspace(lo, hi, n_insertions + 2)[1:-1].astype(int)
    total = np.zeros(n, dtype=int)
    for p in points:
        # data-dependent small stall (0..2 iters), like `if (byte & mask)` blocks
        bits = (pts[:, rng.integers(16)] & rng.choice([0x01, 0x02])) > 0
        extra = (bits.astype(int) + rng.integers(0, 2, size=n)) * samples_per_iter
        for i in range(n):
            d = int(extra[i])
            if d:
                out[i, p + d:] = out[i, p:s - d]
            total[i] += d
    return out, total


def resync_sad(traces: np.ndarray, ref_start: int, ref_len: int,
               max_shift: int, reference: np.ndarray | None = None
               ) -> tuple[np.ndarray, np.ndarray]:
    """Align traces to a reference window using Sum of Absolute Difference.

    For each trace, slide the window [ref_start, ref_start+ref_len) across
    [-max_shift, +max_shift] and choose the shift minimising the SAD against the
    reference window. Traces that cannot be aligned within the range are dropped.

    Returns (aligned_traces, kept_shifts, kept_mask). Shift convention: positive
    means the trace was delayed and is moved left to match the reference.
    kept_mask indexes the input so plaintexts can be kept in step.
    """
    ref = traces[0] if reference is None else reference
    ref_win = ref[ref_start:ref_start + ref_len]
    n, s = traces.shape
    aligned = np.zeros((n, s))
    keep = np.ones(n, dtype=bool)

    # Vectorised SAD: build (n, n_shifts) SAD matrix via a sliding window view.
    shift_vals = np.arange(-max_shift, max_shift + 1)
    valid = (ref_start + shift_vals >= 0) & (ref_start + shift_vals + ref_len <= s)
    shift_vals = shift_vals[valid]
    lo = ref_start + shift_vals[0]
    windows = np.lib.stride_tricks.sliding_window_view(traces, ref_len, axis=1)
    # window starting at (ref_start+shift) -> index (ref_start+shift) in `windows`
    cols = ref_start + shift_vals
    sad = np.abs(windows[:, cols, :] - ref_win[None, None, :]).sum(axis=2)  # (n, n_shifts)
    best = sad.argmin(axis=1)
    shifts = shift_vals[best]
    for i in range(n):
        best_shift = int(shifts[i])
        # realign: move window at (ref_start+shift) back to ref_start
        src_lo = max(0, best_shift)
        src_hi = min(s, s + best_shift)
        dst_lo = max(0, -best_shift)
        length = src_hi - src_lo
        if length <= 0:
            keep[i] = False
            continue
        aligned[i, dst_lo:dst_lo + length] = traces[i, src_lo:src_lo + length]
    return aligned[keep], shifts[keep], keep
