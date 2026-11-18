"""Part A.3 - Traces to disclosure / partial guessing entropy.

For each key byte, measures how many traces the CPA needs before the correct
subkey's peak correlation overtakes every wrong guess and stays on top. This is
the "traces to disclosure" (TTD) view: the attack's cost expressed in trace
count, per byte and overall.

Run:  python a3_traces_to_disclosure.py [campaign]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from sca.cpa import progressive_scores
from sca.data import load_aes

FIG = Path(__file__).parent / "figures"
RES = Path(__file__).parent / "results"


def checkpoints(n: int, step: int) -> list[int]:
    cps = list(range(step, n + 1, step))
    if cps[-1] != n:
        cps.append(n)
    return cps


def traces_to_disclosure(scores: np.ndarray, cps: list[int], key: np.ndarray) -> np.ndarray:
    """First checkpoint from which rank(correct byte) stays 0 to the end."""
    ranks = (scores > np.take_along_axis(scores, key[None, :, None], 2)).sum(2)  # (C, 16)
    ttd = np.full(16, -1)
    for b in range(16):
        stable = ranks[:, b] == 0
        last_fail = np.flatnonzero(~stable)
        first_ok = 0 if last_fail.size == 0 else int(last_fail[-1] + 1)
        ttd[b] = cps[first_ok] if first_ok < len(cps) else -1
    return ttd


def main(campaign: str = "lab4_1") -> None:
    FIG.mkdir(exist_ok=True)
    RES.mkdir(exist_ok=True)
    ts = load_aes(campaign)
    n = min(len(ts.traces), len(ts.plaintexts))
    traces, pts = ts.traces[:n], ts.plaintexts[:n]
    step = max(5, n // 100)
    cps = checkpoints(n, step)

    scores, _ = progressive_scores(traces, pts, cps)        # (C, 16, 256)
    key = scores[-1].argmax(1).astype(np.uint8)             # recovered full key
    ttd = traces_to_disclosure(scores, cps, key)

    print(f"campaign {campaign}: {n} traces, checkpoint step {step}")
    print("traces to disclosure per byte:", list(map(int, ttd)))
    valid = ttd[ttd > 0]
    print(f"max TTD (whole key): {int(valid.max())}  mean: {valid.mean():.1f}")

    # correct-byte rank path per byte, and correct-byte correlation growth
    correct_corr = np.take_along_axis(scores, key[None, :, None], 2)[:, :, 0]  # (C,16)

    # ---- Figure: correct-subkey correlation vs #traces, all bytes -----------
    fig, ax = plt.subplots(figsize=(10, 5))
    for b in range(16):
        ax.plot(cps, correct_corr[:, b], lw=1.0, alpha=0.8)
    ax.set(xlabel="number of traces", ylabel="peak |r| of correct subkey",
           title=f"Correct-subkey correlation converges with trace count - {campaign}")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIG / f"a3_correct_corr_growth_{campaign}.png", dpi=130)
    plt.close(fig)

    # ---- Figure: TTD bar per byte -------------------------------------------
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(range(16), ttd, color="#1f77b4")
    ax.axhline(valid.max(), color="#d62728", ls="--", lw=1,
               label=f"whole-key disclosure = {int(valid.max())} traces")
    ax.set(xlabel="key byte", ylabel="traces to disclosure",
           title=f"Traces to disclosure per key byte - {campaign}", xticks=range(16))
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG / f"a3_ttd_perbyte_{campaign}.png", dpi=130)
    plt.close(fig)

    # ---- Figure: rank of correct byte vs #traces for a few bytes ------------
    ranks = (scores > correct_corr[:, :, None]).sum(2)
    fig, ax = plt.subplots(figsize=(10, 4))
    for b in [0, 5, 10, 15]:
        ax.plot(cps, ranks[:, b], lw=1.2, label=f"byte {b}")
    ax.set(xlabel="number of traces", ylabel="rank of correct subkey (0 = recovered)",
           title=f"Guessing-entropy collapse for selected bytes - {campaign}")
    ax.set_ylim(-2, 60)
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIG / f"a3_rank_vs_traces_{campaign}.png", dpi=130)
    plt.close(fig)

    summary = {
        "campaign": campaign,
        "n_traces": int(n),
        "checkpoint_step": int(step),
        "recovered_key": bytes(key).hex(),
        "ttd_per_byte": [int(x) for x in ttd],
        "whole_key_ttd": int(valid.max()),
        "mean_ttd": round(float(valid.mean()), 1),
    }
    (RES / f"a3_ttd_{campaign}.json").write_text(json.dumps(summary, indent=2))
    print(f"figures -> {FIG}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "lab4_1")
