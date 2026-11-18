# Part A — Side-Channel Attack Findings

All attacks run on **recorded** power traces published by NewAE (the `cwtraces`
0.2.0 data set, SHA-256 pinned in `tools/fetch_reference.py`). No live hardware
was used. Every trace set was captured by NewAE on a ChipWhisperer-Lite with a
CWLITEARM target (STM32F303, Cortex-M4) per the generator notebooks in
`reference/chipwhisperer-jupyter/courses/sca101/generators`.

Reproduce everything with:

```bash
python ../tools/fetch_reference.py      # downloads + checks trace data
python run_all.py                       # writes figures/ and results/
```

The analysis modules under `sca/` are written for this evaluation; they load
the published traces and run the attacks directly rather than executing the
tutorial notebooks.

---

## A.1 — Simple Power Analysis of a password check

**Data:** `lab2_1b_passwords_full.p` (SCA101 Lab 2.1B). The target firmware
(`chipwhisperer/firmware/mcu/basic-passwdcheck/basic-passwdcheck.c`) compares
the entered password against `"h0px3"` byte by byte and `break`s on the first
mismatch:

```c
for(uint8_t i = 0; i < sizeof(correct_passwd); i++){
    if (correct_passwd[i] != passwd[i]){ passbad = 1; break; }
}
```

**Attack:** For each character position the attack queries all 36 candidates
(one trace each) and scores each trace by its sum-of-absolute-difference from
the median of the candidate set. The one correct character runs one extra loop
iteration before `break`, so its trace diverges from the others later in time
and stands out.

**Result (`results/a1_spa_summary.json`):**

| Position | Recovered char | Divergence sample | Margin over next candidate |
|---|---|---|---|
| 0 | `h` | 433 | ×50.5 |
| 1 | `0` | 473 | ×49.6 |
| 2 | `p` | 513 | ×48.4 |
| 3 | `x` | 553 | ×45.6 |
| 4 | `3` | 604 | ×49.7 |

- Full password `h0px3` recovered and **accepted by the device check**.
- **180 device queries** total (36 per position × 5), versus 36⁵ ≈ **60.5 million**
  for blind brute force — a ~340,000× reduction.
- The divergence point advances by ~40 samples (~10 clock cycles) per correct
  character (`figures/a1_spa_divergence_vs_position.png`): the leak is the
  early-abort compare loop.

**Implication for a real device:** any secret compared with a byte-wise
early-exit loop (PIN, password, MAC/tag, serial number) leaks its length-of-
match through timing and power, turning an exponential search into a linear
one. The fix is a constant-time comparison that always touches every byte and
folds the result into a single accumulator. This is exactly the property
reviewed in Part B for the Trezor PIN/passphrase path.

Figures: `a1_spa_correct_vs_wrong.png`, `a1_spa_divergence_vs_position.png`,
`a1_spa_scores_pos0.png`.

---

## A.2 — AES-128 key recovery by Correlation Power Analysis

**Data:** SCA101 AES campaigns `lab4_1` (1000 traces), `lab4_2` (50 traces),
`lab3_3` (2500 traces). Target: TINYAES128C on the same STM32F303.

**Attack:** Classic first-round CPA (Brier–Clavier–Olivier, CHES 2004). For
each of the 16 key bytes and each of the 256 candidate values, the predicted
leakage is the Hamming weight of the first-round S-box output
`HW(SBOX[pt ⊕ k])`. Pearson correlation between that prediction and the
measured samples is computed from running sums (`sca/cpa.py`); the candidate
with the highest peak |correlation| is the recovered byte.

**Result (`results/a2_cpa_*.json`):**

- All three campaigns recover the full key
  **`2b7e151628aed2a6abf7158809cf4f3c`** (the FIPS-197 / AES test key).
- For `lab4_1` and `lab4_2` the recovered key matches NewAE's stored key byte
  for byte (`matches_known_key: true`). The recovery is independently verified
  by re-encrypting a plaintext with the project's own AES model.
- Per-byte confidence (peak of the correct guess ÷ peak of the next-best guess)
  is ≈ 3–4.5× across all bytes — an unambiguous separation.
- Peak-correlation samples step cleanly through the 16 S-box operations of
  round 1 (bytes 0–15 at samples ≈ 1949 → 2669), confirming the model is
  locked onto the first-round SubBytes.

**Implication for a real device:** an unprotected software AES on a small MCU
is fully recoverable from a few dozen to a few hundred traces. The S-box output
is the strongest leak and the standard CPA target; any device holding a
long-term symmetric key in such an implementation must assume full key
extraction given physical access to the power or EM side channel.

Figures: `a2_cpa_perbyte_<campaign>.png` (peak correlation per guess, all 16
bytes), `a2_cpa_byte0_trace_<campaign>.png` (correct subkey vs 255 wrong
guesses over time).

---

## A.3 — Traces to disclosure (partial guessing entropy)

**Question:** how many traces does CPA need before the correct guess for each
byte overtakes every wrong guess and stays on top?

**Method:** CPA is recomputed at increasing trace counts (`progressive_scores`
in `sca/cpa.py`). For each byte the *traces to disclosure* (TTD) is the first
checkpoint after which the correct subkey's rank is 0 for the rest of the run.

**Result (`results/a3_ttd_*.json`):**

| Campaign | TTD per byte (min–max) | Whole-key TTD | Mean |
|---|---|---|---|
| `lab4_1` (1000 traces) | 20 – 50 | **50** | 26.9 |
| `lab4_2` (50 traces)   | 15 – 35 | **35** | 22.5 |

- The whole key is disclosed once the slowest byte converges — 50 traces for
  `lab4_1`. Most bytes fall in 20–30.
- The correct-subkey correlation rises as 1/√N while wrong guesses decay toward
  zero (`a3_correct_corr_growth_*.png`), and the rank of the correct byte drops
  to 0 and stays there (`a3_rank_vs_traces_*.png`).

**Implication for a real device:** TTD is the natural way to express side-
channel resistance — "this key survives *N* traces." An unprotected AES here
survives only tens of traces. A countermeasure is meaningful only if it raises
this number by orders of magnitude (ideally past the attacker's realistic
capture budget), which motivates A.4.

Figures: `a3_ttd_perbyte_<campaign>.png`, `a3_correct_corr_growth_<campaign>.png`,
`a3_rank_vs_traces_<campaign>.png`.

---

## A.4 — A random-delay countermeasure, and defeating it with resynchronisation

**Countermeasure modelled:** the SCA201 `ADD_JITTER` build inserts a
data-dependent random delay before the AES call
(`chipwhisperer/firmware/mcu/simpleserial-aes/simpleserial-aes.c`):

```c
#ifdef ADD_JITTER
for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);
#endif
```

**Reproducibility note (source moved):** NewAE **removed the SCA201 recorded
trace sets** (`Lab_Resync.cwp`, `32bit_AES.cwp`) from
`chipwhisperer-jupyter` in the Nov 2024 commit *"Remove sca201 trace data — to
be replaced"*; only the metadata files survive in git history, and no official
`.npy` download exists (verified against git history and a web search). To keep
Part A reproducible from a single pinned data set, this part **models the
`ADD_JITTER` countermeasure in software on top of the real `lab4_1` captures**
(`sca/resync.py::add_random_delay`): each trace is shifted by
`(pt[0] & 0x0F)` iterations as the firmware does, plus a small sub-sample
residual representing the volatile-loop timing noise that integer alignment
cannot remove. The resynchronisation (`resync_sad`, Sum-of-Absolute-Difference)
is the technique taught in SCA201 Lab 1.1A.

**Result (`results/a4_jitter.json`, 1000-trace base):**

| Implementation | Bytes recovered | Traces to full-key disclosure |
|---|---|---|
| Undefended (aligned) | 16 / 16 | **60** |
| Random delay, naive CPA (no resync) | 0 / 16 | **fails within 1000** |
| Random delay + SAD resync | 16 / 16 | **780** |

- The random delay alone **defeats naive CPA** — the leakage smears across the
  jitter window and no byte is recovered within the 1000-trace budget.
- After SAD resynchronisation the **full key is recovered again**, but it now
  costs **780 traces versus 60** — a **~13× increase**, not a prevention.
- This is the quantitative point: a basic random-delay countermeasure **raises
  the attacker's trace budget but does not stop a prepared attacker** who
  realigns traces first.

**Implication for a real device:** misalignment countermeasures (random delays,
jitter, clock randomisation) raise the bar but are routinely overcome with
trace preprocessing — SAD, cross-correlation, or dynamic time warping (SCA201
Lab 1.1B) for delays dispersed through the computation. They are worth having as
*one layer* but must be combined with real leakage reduction (masking, hiding)
and with a limit on how many operations an attacker can trigger. A device that
relies on jitter alone should be rated as *delaying* key recovery, not
*preventing* it.

Figures: `a4_jitter_traces.png` (aligned vs desynchronised), `a4_resync_traces.png`
(after SAD), `a4_difficulty_comparison.png` (TTD across the three
implementations).

---

## Limitations

- **Recorded traces only.** No board was used; results reflect NewAE's capture
  conditions, not a measurement of any specific shipped product.
- **A.4 jitter is modelled**, not captured, because the SCA201 trace sets are no
  longer distributed. The delay magnitude and data-dependence follow the actual
  firmware, and the SAD resync is the genuine technique; the absolute trace
  counts would differ on real captures but the ordering (undefended ≪ resync ≪
  naive-on-jitter) is the robust, reproducible result.
- The AES target is an 8-bit software implementation. Hardware AES, T-table, or
  masked implementations leak differently and are out of scope for the sample
  data available here.
