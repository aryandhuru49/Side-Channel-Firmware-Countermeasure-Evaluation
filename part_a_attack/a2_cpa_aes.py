"""Part A.2 - Full AES-128 key recovery by Correlation Power Analysis.

Recovers all 16 key bytes from a recorded SCA101 campaign (default lab4_1,
1000 traces, STM32F303 / TINYAES128C). The recovered key is verified by
re-encrypting a known plaintext with the pure-Python AES model and, where the
campaign stores ciphertexts, against the recorded ciphertext.

Run:  python a2_cpa_aes.py [campaign]   # campaign in {lab4_1, lab3_3, lab4_2, lab4_3}
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from sca.aes import encrypt_block
from sca.cpa import cpa
from sca.data import load_aes

FIG = Path(__file__).parent / "figures"
RES = Path(__file__).parent / "results"


def main(campaign: str = "lab4_1") -> None:
    FIG.mkdir(exist_ok=True)
    RES.mkdir(exist_ok=True)
    ts = load_aes(campaign)
    n = min(len(ts.traces), len(ts.plaintexts))
    traces, pts = ts.traces[:n], ts.plaintexts[:n]
    print(f"campaign {campaign}: {traces.shape[0]} traces x {traces.shape[1]} samples")

    corr = cpa(traces, pts)                      # (16, 256, S)
    abs_corr = np.abs(corr)
    peak_per_guess = abs_corr.max(axis=2)        # (16, 256)
    recovered = peak_per_guess.argmax(axis=1).astype(np.uint8)
    peak_sample = np.array([int(abs_corr[b, recovered[b]].argmax()) for b in range(16)])
    conf = np.array([float(np.sort(peak_per_guess[b])[-1] / np.sort(peak_per_guess[b])[-2])
                     for b in range(16)])

    rec_hex = bytes(recovered).hex()
    print(f"recovered key : {rec_hex}")

    # ---- verification -------------------------------------------------------
    ct_model = encrypt_block(bytes(recovered), bytes(pts[0]))
    verified_ct = None
    if ts.ciphertexts is not None:
        verified_ct = ct_model == bytes(ts.ciphertexts[0])
    known_match = None if ts.key is None else (bytes(recovered) == bytes(ts.key))
    print(f"re-encrypt matches recorded ciphertext : {verified_ct}")
    print(f"matches NewAE's stored key             : {known_match}")

    # ---- Figure: correlation vs guess, all 16 bytes -------------------------
    fig, axes = plt.subplots(4, 4, figsize=(13, 9), sharex=True)
    for b, ax in enumerate(axes.flat):
        ax.plot(peak_per_guess[b], color="#bbbbbb", lw=0.6)
        ax.plot([recovered[b]], [peak_per_guess[b, recovered[b]]], "o",
                color="#d62728", ms=4)
        ax.set_title(f"byte {b}: 0x{recovered[b]:02x} (x{conf[b]:.2f})", fontsize=8)
        ax.tick_params(labelsize=6)
    fig.suptitle(f"CPA peak |correlation| per key guess - {campaign} "
                 f"({traces.shape[0]} traces)", fontsize=12)
    fig.supxlabel("key byte guess (0-255)")
    fig.supylabel("peak |Pearson r| over samples")
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    fig.savefig(FIG / f"a2_cpa_perbyte_{campaign}.png", dpi=130)
    plt.close(fig)

    # ---- Figure: correlation trace for byte 0, correct vs others ------------
    fig, ax = plt.subplots(figsize=(9, 4))
    for g in range(256):
        if g != recovered[0]:
            ax.plot(corr[0, g], color="#dddddd", lw=0.4)
    ax.plot(corr[0, recovered[0]], color="#d62728", lw=1.2,
            label=f"correct key 0x{recovered[0]:02x}")
    ax.set(xlabel="sample", ylabel="Pearson r",
           title=f"Byte 0: correct subkey correlation peak vs 255 wrong guesses - {campaign}")
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG / f"a2_cpa_byte0_trace_{campaign}.png", dpi=130)
    plt.close(fig)

    summary = {
        "campaign": campaign,
        "n_traces": int(traces.shape[0]),
        "n_samples": int(traces.shape[1]),
        "recovered_key": rec_hex,
        "known_key": None if ts.key is None else bytes(ts.key).hex(),
        "matches_known_key": None if known_match is None else bool(known_match),
        "reencrypt_matches_recorded_ct": None if verified_ct is None else bool(verified_ct),
        "per_byte_confidence_ratio": [round(float(c), 3) for c in conf],
        "peak_sample": [int(s) for s in peak_sample],
    }
    (RES / f"a2_cpa_{campaign}.json").write_text(json.dumps(summary, indent=2))
    print(f"figures -> {FIG}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "lab4_1")
