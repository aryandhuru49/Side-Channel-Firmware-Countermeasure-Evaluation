"""Part A.1 - Simple power analysis of a password check (SCA101 Lab 2.1B data).

Recovers the 5-character password one character at a time and plots the timing
leak: each correct character moves the point where the correct guess diverges
from the wrong guesses later in the trace.

Run:  python a1_spa_password.py
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from sca.data import load_password_traces
from sca.spa import CHARSET, RecordedPasswordTarget, attack

FIG = Path(__file__).parent / "figures"
RES = Path(__file__).parent / "results"


def main() -> None:
    FIG.mkdir(exist_ok=True)
    RES.mkdir(exist_ok=True)
    recordings = load_password_traces()
    target = RecordedPasswordTarget(recordings)
    result = attack(target)

    accepted = target.check(result.recovered)
    print(f"recovered password : {result.recovered!r}")
    print(f"device accepts it  : {accepted}")
    print(f"total device queries: {result.queries} "
          f"(brute force of 36^5 = {36**5:,})")

    # --- Figure 1: one wrong vs one correct guess at the final position -------
    # A wrong final character collapses, in NewAE's recordings, to the prefix of
    # correct characters followed by a single space (the mismatch position).
    known = result.recovered[:-1]
    correct = np.asarray(recordings[result.recovered])
    wrong = np.asarray(recordings[known + " "])

    fig, ax = plt.subplots(figsize=(9, 4))
    ax.plot(correct.mean(0), color="#1f77b4", lw=1.1,
            label=f"correct last char ({result.recovered[-1]!r})")
    ax.plot(wrong.mean(0), color="#d62728", lw=1.1, label="incorrect last char")
    div = result.positions[-1].divergence_sample
    ax.axvline(div, color="black", ls="--", lw=0.9, label=f"divergence @ sample {div}")
    ax.set(xlabel="sample", ylabel="power (ADC)",
           title="Password check: correct vs incorrect final character")
    ax.set_xlim(0, 900)
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG / "a1_spa_correct_vs_wrong.png", dpi=130)
    plt.close(fig)

    # --- Figure 2: divergence sample grows with each correct character --------
    divs = [p.divergence_sample for p in result.positions]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot(range(1, len(divs) + 1), divs, "o-", color="#1f77b4")
    for i, d in enumerate(divs):
        ax.annotate(result.recovered[i], (i + 1, d), textcoords="offset points",
                    xytext=(0, 8), ha="center", fontsize=10)
    ax.set(xlabel="password position (characters known correct)",
           ylabel="divergence sample",
           title="Timing leak: each correct character delays divergence by ~40 samples")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIG / "a1_spa_divergence_vs_position.png", dpi=130)
    plt.close(fig)

    # --- Figure 3: SAD score per candidate at position 0 ----------------------
    pos0 = result.positions[0]
    chars = list(CHARSET)
    vals = [pos0.scores[c] for c in chars]
    fig, ax = plt.subplots(figsize=(10, 3.5))
    colors = ["#d62728" if c == pos0.best_char else "#9ecae1" for c in chars]
    ax.bar(chars, vals, color=colors)
    ax.set(xlabel="candidate first character", ylabel="SAD vs median of guesses",
           title=f"Position 0: {pos0.best_char!r} stands out "
                 f"(margin x{pos0.margin:.1f} over next)")
    fig.tight_layout()
    fig.savefig(FIG / "a1_spa_scores_pos0.png", dpi=130)
    plt.close(fig)

    summary = {
        "recovered": result.recovered,
        "accepted_by_device": bool(accepted),
        "device_queries": result.queries,
        "bruteforce_space": 36 ** 5,
        "positions": [
            {"position": p.position, "char": p.best_char,
             "divergence_sample": p.divergence_sample, "margin": round(p.margin, 2)}
            for p in result.positions
        ],
    }
    (RES / "a1_spa_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"figures -> {FIG}")


if __name__ == "__main__":
    main()
