# Security Evaluation Report
## Side-Channel and Fault-Injection Resistance of a Cryptographic Implementation and a Hardware Wallet Firmware

**Document type:** Independent security evaluation (portfolio exercise)
**Evaluation basis:** Recorded power-analysis traces (ChipWhisperer SCA101) and
source review of `trezor/trezor-firmware`.
**Date:** 2026-11-18
**Status:** Final

---

## 1. One-Page Summary

This evaluation does two things a hardware/logical security lab does: it *attacks*
a cryptographic implementation through physical leakage, and it *reviews* a
shipping product's source to judge whether it resists that same attack class.

**Part A — Attack (recorded traces).** Working only from power traces published
with the ChipWhisperer tutorials — no live board — the evaluation:

- recovered a 5-character device password from a byte-wise compare that exits
  early, in **180 measurements** instead of ~60 million brute-force guesses;
- recovered a **full AES-128 key** from an unprotected 8-bit software AES by
  Correlation Power Analysis, confirmed against the known key;
- measured **traces to disclosure**: the whole key fell in **~50 traces**;
- showed that a **random-delay countermeasure** only raises the cost — after
  trace resynchronisation the key was recovered again at ~13× the traces (780
  vs 60), not prevented.

**Part B — Firmware review (Trezor).** A source-level review found a mature,
layered defense against exactly this class of attack: constant-time **and**
power-masked PIN comparison; wallet secrets handled with ChaCha20-Poly1305 and
PBKDF2 rather than table AES; fault-injection hardening (a glitch-resistant
boolean encoding `0xAAAAAAAA`, loop-completion checks, a fail-counter incremented
before the PIN check and re-verified, and a fault handler that converges on a
wipe); Ed25519 threshold secure boot that halts on failure; and binding of the
PIN-derived key to a secure element so a flash dump cannot be brute-forced
off-chip.

**Overall posture.** The unprotected reference implementation in Part A is
trivially broken and stands for "what not to ship." The Trezor firmware in Part
B answers each published Trezor One glitch attack with a specific, cited
mitigation. The **material residual risks** are (a) builds **without a secure
element**, where PIN-brute-force resistance falls back to PBKDF2 and a software
counter; (b) **anti-rollback** enforcement and root-key protection, which a
source-only review could not fully trace; and (c) the **per-target AES path**,
where a software table AES on a secret would reintroduce the Part A leak. These
are flagged, not resolved, and warrant hardware-in-the-loop follow-up.

Attack-potential ratings below use a scheme modelled on PCI PTS (identification
effort + exploitation effort → an attack-potential score and a derived
feasibility). Unprotected targets rate **Low/Moderate** attack potential (easy
to break). The Trezor mitigations push the equivalent attacks to **High /
Beyond-High** potential, i.e. not feasible for the modelled attacker.

---

## 2. Scope, Method, and Limitations

**In scope.** Power side-channel key/secret recovery and fault-injection bypass
of secret-dependent comparisons and secure boot.

**Method.**
- Part A attacks run against NewAE's recorded `cwtraces` 0.2.0 data set
  (SHA-256 pinned). Analysis code was written for this evaluation (see
  `part_a_attack/sca/`); the tutorial notebooks were not executed.
- Part B is a read-only source review of `trezor/trezor-firmware` at a pinned
  commit, every claim cited to file and function.

**Rating scheme.** Each attack is scored with a PCI-PTS-style *attack potential*
table split into **Identification** (one-off cost to develop the attack) and
**Exploitation** (per-device cost to repeat it), over the factors *Attack time,
Expertise, Target knowledge, Equipment, Samples/Access*. Higher points = harder
attack = better defense. The band (Low → Beyond-High) gives the feasibility
verdict.

**Limitations.**
- **No live hardware.** Part A uses recorded traces; absolute numbers reflect
  NewAE's capture conditions, not a measurement of any shipped device.
- **A.4 countermeasure is modelled**, not captured — the original SCA201 jitter
  traces are no longer distributed (removed from the upstream repo Nov 2024).
  The delay magnitude and data-dependence follow the real firmware and the
  resync is the genuine technique; the *ordering* of difficulty is the robust
  result, not the exact trace counts.
- **Part B is source-only.** It cannot measure real leakage or glitch success
  rates, and three areas (SE-less builds, anti-rollback, per-target AES) are
  explicitly left unconfirmed.

---

## 3. Rating Model (reference)

**Attack-potential points → band** (summed over Identification + Exploitation):

| Total points | Band | Feasibility for the modelled attacker |
|---|---|---|
| 0–9 | Low | Routinely feasible |
| 10–13 | Moderate | Feasible with basic SCA skills/gear |
| 14–19 | High | Feasible only for a specialised lab |
| 20–24 | Beyond-High | Impractical |
| 25+ | Beyond-High (hardened) | Not feasible as modelled |

Per-factor guidance (points grow with difficulty): *Expertise* Layperson 0 →
Proficient 2 → Expert 5 → Multiple-expert 7; *Equipment* Standard 0 → Specialised
4 → Bespoke 7; *Access/Samples* Few 0 → Many 4; *Time* <1 day 0 → >1 month 7.

---

## 4. Detailed Findings

### Finding A-1 — Timing/SPA password recovery (early-exit comparison)

- **Attack path.** Query the device's password check once per candidate
  character; the correct character runs one extra compare-loop iteration before
  `break`, moving the power-trace divergence ~40 samples later. Scoring each
  trace against the group median recovers the character; repeat per position.
  (Target: `basic-passwdcheck.c`; evidence: `part_a_attack/figures/a1_*`.)
- **What the attacker needs.** *Equipment:* a power/EM probe and a low-cost
  scope (or, as here, recorded traces). *Skill:* basic SCA. *Access:* ability to
  submit guesses and observe one trace each; 36 × 5 = 180 traces. *Time:* hours.
- **Feasibility.** High in practice — the leak is first-order and visible in a
  single trace per guess.
- **Result.** Password `h0px3` recovered, device-accepted, 180 vs ~6.0×10⁷.
- **Countermeasure (missing here / present in Part B).** Constant-time compare
  that touches every byte with no data-dependent branch — exactly Trezor's
  `secequal` (`storage/storage.c:191`).

**Attack-potential rating**

| Factor | Identification | Exploitation |
|---|---|---|
| Time | 1 | 0 |
| Expertise | 2 (Proficient) | 2 |
| Target knowledge | 1 | 1 |
| Equipment | 1 | 1 |
| Access/Samples | 0 | 0 |
| **Subtotal** | **5** | **4** |
| **Total** | **9** | |
| **Band** | **Low** — routinely feasible | |

---

### Finding A-2 — AES-128 key recovery by CPA

- **Attack path.** First-round CPA with a Hamming-weight model of the S-box
  output `HW(SBOX[pt ⊕ k])`; the candidate maximising Pearson correlation is the
  key byte, per byte. (Evidence: `part_a_attack/figures/a2_*`,
  `results/a2_cpa_*.json`.)
- **What the attacker needs.** *Equipment:* probe + scope (recorded here).
  *Skill:* standard CPA. *Access:* tens–hundreds of traces with known plaintext.
  *Time:* hours once tooling exists.
- **Feasibility.** High against an unprotected software AES.
- **Result.** Full key `2b7e…4f3c` from all three campaigns; verified against the
  stored key and a reference AES.
- **Countermeasure (missing here).** Masking/hiding of the S-box computation; or,
  as in Part B, keeping long-term secrets out of a table AES (ChaCha20 + PBKDF2,
  and hardware/SE AES).

**Attack-potential rating**

| Factor | Identification | Exploitation |
|---|---|---|
| Time | 2 | 0 |
| Expertise | 2 | 2 |
| Target knowledge | 2 | 1 |
| Equipment | 2 | 1 |
| Access/Samples | 1 | 1 |
| **Subtotal** | **9** | **5** |
| **Total** | **14** | |
| **Band** | **High identification, Low exploitation** → overall feasible for an SCA-capable attacker; ~**Moderate** | |

*(Identification is the one-off cost of building the CPA; once built, each device
costs only tens of traces — the exploitation column — which is why unprotected
AES is considered broken.)*

---

### Finding A-3 — Traces to disclosure (quantified resistance)

- **Finding.** Whole-key disclosure needs ~**50 traces** (`lab4_1`) / ~**35**
  (`lab4_2`); most bytes 20–30. This is the resistance metric: the key survives
  only tens of operations. (Evidence: `results/a3_ttd_*.json`,
  `figures/a3_*`.)
- **Implication.** A countermeasure is only meaningful if it raises this by orders
  of magnitude, past the attacker's realistic capture budget. This metric is how
  the Part B defenses should ultimately be validated on hardware.

*(No separate rating — this quantifies A-2.)*

---

### Finding A-4 — Random-delay countermeasure is a speed bump, not a wall

- **Attack path.** A data-dependent random pre-AES delay desynchronises traces
  and defeats naive CPA (0/16 bytes within budget). Sum-of-Absolute-Difference
  **resynchronisation** realigns the traces; CPA then recovers the full key
  again. (Evidence: `figures/a4_difficulty_comparison.png`,
  `results/a4_jitter.json`.)
- **Result.** Undefended 60 traces → jitter+resync **780 traces** (×13), full
  recovery; un-resynced jitter fails. The countermeasure **raises cost, does not
  prevent**.
- **What the attacker needs beyond A-2.** Trace preprocessing skill (SAD, or DTW
  for delays dispersed through the rounds) and a larger capture budget.
- **Countermeasure (adequate vs not).** Jitter alone → delays only. It must be
  combined with leakage reduction (masking) **and** a hard limit on attacker
  queries — which in Part B is the secure-element attempt counter.

**Attack-potential rating (attack on the jittered target)**

| Factor | Identification | Exploitation |
|---|---|---|
| Time | 3 | 1 |
| Expertise | 5 (Expert: resync) | 2 |
| Target knowledge | 2 | 1 |
| Equipment | 2 | 2 |
| Access/Samples | 2 (more traces) | 2 |
| **Subtotal** | **14** | **8** |
| **Total** | **22** | |
| **Band** | **Beyond-High identification**, Moderate exploitation → raises the bar materially but **does not stop** a prepared lab | |

---

### Finding B-1 — PIN/passphrase comparison (Trezor): constant-time, masked, no passphrase oracle

- **Observed.** `secequal` accumulates over all bytes (`storage/storage.c:191`);
  `secequal32` adds per-word random masking (`:211`); PVC check at `:1133`.
  Passphrase is an input to BIP-39 seed derivation, never compared
  (`core/src/apps/common/mnemonic.py:52`).
- **Effect.** Neutralises Finding A-1's attack class and the first-order power
  leak of A-2 on the compare.

**Attack-potential rating (SPA/CPA on the PIN compare)**

| Factor | Identification | Exploitation |
|---|---|---|
| Time | 4 | 2 |
| Expertise | 5 | 2 |
| Target knowledge | 3 | 1 |
| Equipment | 4 (bespoke to beat masking) | 3 |
| Access/Samples | 3 (counter-limited) | 3 |
| **Subtotal** | **19** | **11** |
| **Total** | **30** | |
| **Band** | **Beyond-High (hardened)** — not feasible as modelled; attempt counter caps samples | |

---

### Finding B-2 — Fault-injection hardening (Trezor)

- **Observed.** `sectrue=0xAAAAAAAA` (`secbool.h:25`); loop-completion checks →
  `handle_fault` (`storage.c:203`,`229`); PIN fail counter incremented *before*
  the check and re-verified (`storage.c:1202`–`1212`); re-entrant fault handler
  wipes (`storage.c:1816`); double tag compare (`storage.c:438`–`459`).
- **Effect.** A single glitch cannot forge an accepted boolean or silently skip
  the compare; sustained glitching converges on storage wipe.

**Attack-potential rating (glitch-to-bypass PIN)**

| Factor | Identification | Exploitation |
|---|---|---|
| Time | 5 | 3 |
| Expertise | 5 | 3 |
| Target knowledge | 3 | 2 |
| Equipment | 4 | 3 |
| Access/Samples | 2 | 2 |
| **Subtotal** | **19** | **13** |
| **Total** | **32** | |
| **Band** | **Beyond-High (hardened)** | |

---

### Finding B-3 — Secure boot (Trezor)

- **Observed.** Ed25519 CoSi *m*-of-*n* threshold verification of the image hash
  (`core/embed/sec/image/image.c:89`,`178`–`191`); staged boardloader →
  bootloader → firmware; `ensure(...)` fatal-halt on failure
  (`boot_image.c:121`).
- **Effect.** Unsigned/tampered code does not execute.
- **Flagged (unconfirmed in source-only review).** Anti-rollback version
  enforcement and root-key storage/protection.

**Attack-potential rating (run unsigned firmware)**

| Factor | Identification | Exploitation |
|---|---|---|
| Time | 5 | 3 |
| Expertise | 7 (break/forge Ed25519 threshold → infeasible) | — |
| Target knowledge | 3 | 2 |
| Equipment | 4 | 3 |
| Access/Samples | 2 | 2 |
| **Subtotal** | **21** | — |
| **Band** | **Beyond-High** for signature forgery; residual risk sits in anti-rollback (*flagged*, not rated) | |

---

### Finding B-4 — Secure-element binding of the PIN-derived key (Trezor)

- **Observed.** KEK bound to Optiga/Tropic: `optiga_pin_stretch_cmac_ecdh`
  (`storage.c:705`), `tropic_pin_set` + Mac-and-Destroy (`:730`),
  `tropic_pin_set_kek_masks` (`:744`); PBKDF2 stretch first (`:588`–`611`).
- **Effect.** Directly answers the Kraken dump-then-brute-force attack: the KEK
  cannot be reconstructed from dumped flash without the SE's rate-limited secret.
- **Residual (flagged).** On **SE-less builds** the fallback is
  `memcpy(kek, stretched_pins[0], …)` (`storage.c:749`) — PBKDF2 + software
  counter only; brute-force resistance then depends on PIN entropy and iteration
  count. **Evaluate per product.**

**Attack-potential rating (offline PIN brute-force after flash dump)**

| Context | Total | Band |
|---|---|---|
| SE-equipped (Optiga/Tropic) | ~30 | **Beyond-High (hardened)** — SE counter caps attempts |
| **SE-less build** | ~**12** | **Moderate** — feasible if PIN entropy/iterations are low ⚠ |

---

## 5. Summary of Ratings

| Finding | Target | Band | Verdict |
|---|---|---|---|
| A-1 SPA password | Unprotected compare | Low | Broken |
| A-2 CPA AES-128 | Unprotected SW AES | Moderate | Broken (≈50 traces) |
| A-4 CPA vs random delay | Jittered SW AES | Beyond-High ident. | Delayed ×13, not prevented |
| B-1 PIN compare | Trezor core | Beyond-High (hardened) | Resistant |
| B-2 Fault hardening | Trezor core | Beyond-High (hardened) | Resistant |
| B-3 Secure boot | Trezor core | Beyond-High (signing) | Resistant; anti-rollback flagged |
| B-4 KEK ↔ secure element | Trezor core | Beyond-High (SE) / **Moderate (SE-less ⚠)** | Resistant with SE; evaluate SE-less |

---

## 6. Conclusion on Overall Security Posture

The contrast between the two halves of this evaluation is the point. An
unprotected cryptographic implementation (Part A) leaks its secrets through
timing and power so readily that a full AES key falls in about fifty traces and
a password in a few hundred guesses; a basic random-delay countermeasure only
multiplies the attacker's trace budget rather than stopping them.

The Trezor firmware (Part B) is a credible example of the opposite: for every
attack demonstrated or published in this class, there is a specific,
source-cited mitigation — constant-time and masked comparison, glitch-hardened
booleans and redundant fault checks, threshold-signed secure boot, and binding
of the PIN-derived key to a rate-limited secure element. Against the attacker
modelled here, those mitigations move the equivalent attacks from "routinely
feasible" to "not feasible as modelled."

The posture is therefore **strong on secure-element-equipped devices**, with
residual risk concentrated in three places that a source-only review cannot
close and that deserve hardware-in-the-loop follow-up:

1. **Secure-element-less builds**, where PIN brute-force resistance degrades to
   PBKDF2 plus a software counter (Finding B-4).
2. **Anti-rollback and root-key protection** in the boot chain (Finding B-3).
3. **Per-target AES selection**, to ensure no secret is ever processed by the
   software table AES (Finding B-2 in Part B review).

A full evaluation would next capture real traces from target hardware to put
measured traces-to-disclosure numbers behind the Part B mitigations, and would
exercise glitch campaigns against the fault defenses rather than reading them.

---

### Appendix — Evidence index

- Part A code/figures/results: `part_a_attack/` (`FINDINGS.md`, `figures/`,
  `results/`).
- Part B citations: `part_b_firmware_review/REVIEW.md` (all line numbers at the
  pinned `trezor-firmware` commit in `tools/fetch_reference.py`).
- Reproduction: `README.md`.
