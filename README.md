# Side-Channel and Firmware Countermeasure Evaluation

A security-evaluation portfolio project in the style of a hardware/logical
security test lab. It does three things:

- **Part A — Attack.** Break a cryptographic implementation through power
  side-channel leakage: simple power analysis of a password check, full AES-128
  key recovery by Correlation Power Analysis, a traces-to-disclosure analysis,
  and a demonstration that a random-delay countermeasure only *raises* the
  attack cost rather than preventing it.
- **Part B — Firmware review.** A source-level review of real wallet firmware
  (Trezor) against that same class of attack: constant-time secret comparison,
  branch/table-lookup leakage, fault-injection defenses, and secure boot.
- **Part C — Evaluation report.** A single lab-style report that rates each
  finding using an attack-potential scheme modelled on PCI PTS (identification
  effort and exploitation effort), with a one-page summary and a posture
  conclusion.

## Scope and limitation

> **All attacks in Part A run on *recorded* power traces published by NewAE, not
> on live hardware.** No ChipWhisperer board was used. The trace sets are the
> `cwtraces` 0.2.0 data distributed with the ChipWhisperer Jupyter tutorials
> (SCA101). Part B reviews the public Trezor firmware source as read-only
> reference material. Nothing here is an attack against, or a measurement of, a
> deployed device; the AES target is an 8-bit software implementation used for
> teaching. See `part_a_attack/FINDINGS.md` for per-result caveats, including
> the one place (A.4) where a countermeasure is *modelled* on top of real
> traces because the original SCA201 captures are no longer distributed.

All tooling is free and open source (Python, NumPy, Matplotlib).

## Repository layout

```
README.md
requirements.txt
tools/fetch_reference.py        # downloads + checksums trace data, clones reference repos
part_a_attack/                  # side-channel attack code, figures, FINDINGS.md
part_b_firmware_review/         # Trezor source review
part_c_report/                  # evaluation_report.md
data/        (generated)        # trace data, not committed
reference/   (generated)        # read-only upstream repos, not committed
```

## Reproducing

Tested with Python 3.12 on Windows 11.

```bash
python -m pip install -r requirements.txt
```

### Part A

```bash
python tools/fetch_reference.py --no-repos     # fetch + verify trace data only
cd part_a_attack
python run_all.py                              # all attacks -> figures/ and results/
```

Or run individual stages:

```bash
python a1_spa_password.py            # SPA on the password check
python a2_cpa_aes.py lab4_1          # CPA AES-128 key recovery
python a3_traces_to_disclosure.py lab4_1
python a4_jitter_countermeasure.py   # jitter + SAD resynchronisation
```

Outputs land in `part_a_attack/figures/` (PNG) and `part_a_attack/results/`
(JSON). `part_a_attack/FINDINGS.md` explains each result.

### Part B

```bash
python tools/fetch_reference.py       # also clones trezor-firmware at a pinned commit
```

The review (`part_b_firmware_review/REVIEW.md`) cites specific files, functions,
and line ranges in `reference/trezor-firmware/`, pinned to the commit recorded
in `tools/fetch_reference.py`.

### Part C

`part_c_report/evaluation_report.md` is the standalone evaluation document; it
references the Part A figures and Part B citations.

## Data provenance

- **Traces:** `cwtraces` 0.2.0 wheel from PyPI, SHA-256 pinned in
  `tools/fetch_reference.py`. Only the data files are unpacked; no code from the
  wheel is executed. The password-trace pickle is loaded through a restricted
  unpickler that permits only NumPy array reconstruction.
- **Reference repos (read-only), pinned commits:**
  `newaetech/chipwhisperer-jupyter` and `trezor/trezor-firmware`.
