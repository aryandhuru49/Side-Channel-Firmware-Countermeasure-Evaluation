"""Part A.4 - Attacking a jittered AES and defeating it with resynchronisation.

The original SCA201 recorded trace sets (Lab_Resync.cwp, 32bit_AES.cwp) were
removed from newaetech/chipwhisperer-jupyter in Nov 2024 ("Remove sca201 trace
data - to be replaced"); only their metadata survives in git history, and no
official .npy download exists. To keep Part A reproducible from one pinned data
set, this script models the SCA201 random-delay countermeasure in software on
top of the real SCA101 lab4_1 captures:

  firmware (simpleserial-aes.c, EXTRA_OPTS=ADD_JITTER):
      for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);

i.e. a 0..15 iteration data-dependent delay before AES. `add_random_delay`
reproduces that shift per trace, plus a small sub-sample residual that integer
SAD cannot remove. We then compare three implementations by traces-to-disclosure:

  1. undefended (aligned)         - the real captures
  2. random delay, naive attacker - no resynchronisation
  3. random delay + SAD resync    - SCA201 Lab 1.1A technique

Run:  python a4_jitter_countermeasure.py
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from sca.cpa import progressive_scores
from sca.data import load_aes
from sca.resync import add_random_delay, resync_sad

FIG = Path(__file__).parent / "figures"
RES = Path(__file__).parent / "results"

AES_REGION = (1900, 2900)   # first-round leakage window in these captures
REF_START, REF_LEN, MAX_SHIFT = 1900, 150, 40
RESIDUAL = 1.2              # sub-sample jitter left after integer resync


def ttd(traces, pts, key, step=20):
    cps = list(range(step, len(traces) + 1, step))
    scores, _ = progressive_scores(traces, pts, cps)
    correct = np.take_along_axis(scores, key[None, :, None], 2)[:, :, 0]
    rank = (scores > correct[:, :, None]).sum(2)
    per_byte = []
    for b in range(16):
        fail = np.flatnonzero(rank[:, b] != 0)
        first_ok = 0 if fail.size == 0 else int(fail[-1] + 1)
        per_byte.append(cps[first_ok] if first_ok < len(cps) else -1)
    recovered = [x for x in per_byte if x > 0]
    return {"per_byte": per_byte,
            "whole_key_ttd": max(recovered) if recovered else -1,
            "bytes_recovered": len(recovered)}


def main() -> None:
    FIG.mkdir(exist_ok=True)
    RES.mkdir(exist_ok=True)
    ts = load_aes("lab4_1")
    n = 1000
    tr, pt = ts.traces[:n], ts.plaintexts[:n]
    key = np.asarray(ts.key)

    jit, delays = add_random_delay(tr, pt, residual=RESIDUAL)
    aligned_jit, shifts, keep = resync_sad(jit, REF_START, REF_LEN, MAX_SHIFT)
    pt_keep = pt[keep]

    print(f"jitter delay range: {delays.min()}-{delays.max()} samples; "
          f"resync kept {keep.sum()}/{n} traces, shift range "
          f"{shifts.min()}..{shifts.max()}")

    r_aligned = ttd(tr, pt, key)
    r_jitter = ttd(jit, pt, key)
    r_resync = ttd(aligned_jit, pt_keep, key)

    for label, r in [("undefended", r_aligned), ("jitter/no-resync", r_jitter),
                     ("jitter+resync", r_resync)]:
        print(f"{label:18s} bytes={r['bytes_recovered']:2d}/16  "
              f"whole-key TTD={r['whole_key_ttd']}")

    # ---- Figure: a jittered trace vs the aligned original -------------------
    fig, axes = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
    idx = np.argsort(delays)[::-1][:12]
    for i in idx:
        axes[0].plot(tr[i, AES_REGION[0]:AES_REGION[1]], color="#1f77b4", lw=0.5, alpha=0.6)
        axes[1].plot(jit[i, AES_REGION[0]:AES_REGION[1]], color="#d62728", lw=0.5, alpha=0.6)
    axes[0].set_title("Aligned captures (first-round region)")
    axes[1].set_title("After random-delay countermeasure (same traces, desynchronised)")
    axes[1].set_xlabel("sample (relative to region start)")
    fig.tight_layout()
    fig.savefig(FIG / "a4_jitter_traces.png", dpi=130)
    plt.close(fig)

    # ---- Figure: resync realigns the features ------------------------------
    # Pick kept traces that originally had the largest delays, in aligned order.
    kept_idx = np.flatnonzero(keep)
    big_delay_kept = kept_idx[np.argsort(delays[kept_idx])[::-1][:12]]
    pos_in_aligned = {orig: p for p, orig in enumerate(kept_idx)}
    fig, ax = plt.subplots(figsize=(10, 4))
    for orig in big_delay_kept:
        ax.plot(aligned_jit[pos_in_aligned[orig], AES_REGION[0]:AES_REGION[1]],
                color="#2ca02c", lw=0.5, alpha=0.6)
    ax.set(title="After SAD resynchronisation (features realigned)",
           xlabel="sample (relative to region start)")
    fig.tight_layout()
    fig.savefig(FIG / "a4_resync_traces.png", dpi=130)
    plt.close(fig)

    # ---- Figure: TTD comparison across implementations ---------------------
    labels = ["undefended", "jitter\n(no resync)", "jitter\n+ SAD resync"]
    vals = [r_aligned["whole_key_ttd"], r_jitter["whole_key_ttd"], r_resync["whole_key_ttd"]]
    recs = [r_aligned["bytes_recovered"], r_jitter["bytes_recovered"], r_resync["bytes_recovered"]]
    disp = [v if v > 0 else n for v in vals]  # failed attack drawn at full budget
    fig, ax = plt.subplots(figsize=(8, 5))
    colors = ["#1f77b4", "#d62728", "#2ca02c"]
    bars = ax.bar(labels, disp, color=colors)
    for bar, v, rc in zip(bars, vals, recs):
        txt = f"{v} traces\n{rc}/16 bytes" if v > 0 else f">{n} (failed)\n{rc}/16 bytes"
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 10, txt,
                ha="center", va="bottom", fontsize=9)
    ax.set(ylabel="traces to full-key disclosure",
           title="Attack difficulty by implementation (lab4_1 base, CPA)")
    ax.set_ylim(0, n * 1.15)
    fig.tight_layout()
    fig.savefig(FIG / "a4_difficulty_comparison.png", dpi=130)
    plt.close(fig)

    summary = {
        "base_campaign": "lab4_1",
        "n_traces": n,
        "model": "SCA201 ADD_JITTER random delay applied in software to real captures",
        "jitter_delay_samples": [int(delays.min()), int(delays.max())],
        "residual_subsample_jitter": RESIDUAL,
        "resync": {"ref_start": REF_START, "ref_len": REF_LEN, "max_shift": MAX_SHIFT,
                   "kept": int(keep.sum())},
        "results": {
            "undefended": r_aligned,
            "jitter_no_resync": r_jitter,
            "jitter_plus_resync": r_resync,
        },
        "difficulty_multiplier_resync_vs_undefended":
            round(r_resync["whole_key_ttd"] / r_aligned["whole_key_ttd"], 1)
            if r_aligned["whole_key_ttd"] > 0 else None,
    }
    (RES / "a4_jitter.json").write_text(json.dumps(summary, indent=2))
    print(f"figures -> {FIG}")


if __name__ == "__main__":
    main()
