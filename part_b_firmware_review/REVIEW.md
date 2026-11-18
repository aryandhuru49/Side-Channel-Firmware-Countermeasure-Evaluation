# Part B — Trezor Firmware Countermeasure Review

**Subject:** `trezor/trezor-firmware`, read-only, pinned at commit
`57b905e5355c9454e8677a33e458cf31e661406c` (2026-11-18), fetched by
`tools/fetch_reference.py`. All line numbers refer to that commit.

**Method:** source review only. Every claim below cites a specific file and
function. Where behaviour could not be confirmed from the source it is stated
as such rather than assumed. "core" = the Trezor Safe / Model T firmware under
`core/` and `storage/`; "legacy" = the Trezor One firmware under `legacy/`.

This review targets the same attack class as Part A: an attacker with physical
access using power/EM side channels and voltage/clock fault injection against
secret-dependent comparisons and the boot chain.

---

## B.1 — Is PIN and passphrase comparison constant-time, and where is it enforced?

**PIN: yes, constant-time, and additionally masked.** The PIN is never compared
to a stored plaintext. Entry of a PIN derives a key-encryption key (KEK); the
firmware decrypts a key block and compares the resulting Poly1305 tag against a
stored *PIN verification code* (PVC) using a constant-time comparator.

- `secequal()` — `storage/storage.c:191`. Accumulates `diff |= *p1 ^ *p2` over
  **all** `n` bytes with no early exit, then returns `diff ? secfalse : sectrue`.
  This is the exact opposite of the Part A.1 early-exit loop, so it leaks
  neither match length nor position.
- `secequal32()` — `storage/storage.c:211`. Same, on 32-bit words, with a
  **random mask** per word: `diff |= (*p1 + mask - *p2) ^ mask`, `mask =
  random32()`. This hides the Hamming weight of the compared values from a
  power attacker (a hiding countermeasure against the very CPA-style leak
  demonstrated in Part A.2).
- Enforcement point: the PVC check is `secequal32(tag, pvc, PVC_SIZE)` at
  `storage/storage.c:1133`, inside `decrypt_dek()` on the unlock path.

**Passphrase: not compared at all (by design).** There is no passphrase
equality check to be constant-time or not. The passphrase is an input to BIP-39
seed derivation — `bip39.seed(mnemonic_secret.decode(), passphrase, ...)` at
`core/src/apps/common/mnemonic.py:52`. A different passphrase deterministically
yields a *different* wallet, so there is no stored secret to compare against and
no oracle to leak. This is a stronger position than constant-time comparison.

**Assessment:** meets the constant-time requirement for the PIN, and removes the
comparison entirely for the passphrase. The masking in `secequal32` goes beyond
constant time toward power-leakage hiding.

---

## B.2 — Does the cryptographic code avoid secret-dependent branches and table lookups?

**On the secret (wallet/storage) path: yes.** Storage confidentiality and the
PIN KDF use primitives that are branch- and table-free on secret data:

- **ChaCha20-Poly1305** for storage encryption/authentication —
  `#include "chacha20poly1305/rfc7539.h"` (`storage/storage.c:28`), used at
  `decrypt_dek()` (`storage/storage.c:1122`–`1133`). ChaCha20 is an ARX stream
  cipher (add-rotate-xor); it has no S-box tables and no secret-dependent
  branching, so it does not have the first-round S-box leak that Part A.2
  exploited in table/S-box AES.
- **PBKDF2-HMAC-SHA256** for PIN stretching — `storage/storage.c:588`–`611`
  (`mcu_pin_stretch`). SHA-256 is likewise table-free on secret data.

**A data-dependent table AES does exist, but not on the seed path.** The
Brian-Gladman AES in `crypto/aes/` uses T-tables (`four_tables`/`one_table`,
`crypto/aes/aesopt.h:724`–`746`; `fwd_rnd`, `crypto/aes/aescrypt.c:81`), which
are classic secret-dependent lookups. Its callers in `core/embed` are the
secure-element transport (`core/embed/sec/optiga/optiga_transport.c`),
production test, and `core/embed/sec/secure_aes/`. On the STM32U5 target
`secure_aes` uses the **hardware AES (SAES) peripheral**
(`core/embed/sec/secure_aes/stm32u5/secure_aes.c`), not the software tables.

**Assessment:** the wallet-secret cryptography avoids secret-dependent tables
and branches. The table-AES library is present but is confined to
secure-element transport and hardware-backed AES, not to deriving or protecting
the seed. **Caveat / unclear:** I did not trace every build target's
`secure_aes` path; on any target where the software table AES (rather than the
SAES peripheral) handled a secret, the Part A.2 leak would apply. This should be
confirmed per hardware target before relying on it.

---

## B.3 — What fault-injection defenses exist?

Multiple, layered, and explicit in the code:

1. **Glitch-hardened boolean encoding.** `sectrue = 0xAAAAAAAAU`,
   `secfalse = 0x00000000U` (`core/embed/rtl/inc/rtl/secbool.h:25`–`26`).
   Security decisions test for the exact `0xAAAAAAAA` pattern, so a single
   bit-flip from a glitch cannot turn a `secfalse` into an accepted `sectrue`.
2. **Loop-completion checks.** `secequal`/`secequal32` and the auth-sum loop
   verify the loop counter reached `n` and call `handle_fault("loop completion
   check")` otherwise (`storage/storage.c:203`, `229`, `357`) — catching a
   glitch that skips the comparison loop.
3. **Fail-counter-before-check.** The PIN failure counter is incremented *before*
   the PIN is verified and reset only on success (`storage/storage.c:1202`–`1205`),
   so a glitch that interrupts the check still leaves the attempt counted. The
   increment is then **re-read and verified**: `ctr + 1 != ctr_ck` →
   `handle_fault("PIN counter increment")` (`storage/storage.c:1211`–`1212`).
4. **Central fault handler.** `__handle_fault()` (`storage/storage.c:1812`)
   burns a PIN-fail counter and halts via `__fatal_error`; if it is re-entered
   (a fault during fault handling, i.e. a sustained glitching campaign) it
   **wipes storage** (`storage/storage.c:1816`–`1820`).
5. **Double computation + comparison** of the wipe-code tag:
   `computed_tag1` vs `computed_tag2` before acting
   (`storage/storage.c:438`–`459`), with `wait_random()` interleaved — a
   redundant-check defense against a glitch on a single evaluation.
6. **Timing randomisation.** `wait_random()` is placed around sensitive compares
   (`storage/storage.c:444`–`462`, `1131`) to desynchronise an attacker's glitch
   timing — the same desync that Part A.4 showed raises side-channel cost.
7. **Crypto-library fault hook.** `tc_fault_handler()` and the secp256k1
   illegal/error callbacks route to `system_exit_error`
   (`core/embed/crypto/src/fault_handler.c:26`–`41`), halting on an internal
   crypto inconsistency rather than continuing.

**Assessment:** this is a mature, defense-in-depth set of fault countermeasures:
redundant encoding, redundant checks, loop-integrity checks, and a fault counter
that converges on wipe. It directly addresses the glitch-to-bypass class.

---

## B.4 — How does secure boot verify signatures, and what happens on failure?

**Verification:** an **Ed25519 CoSi *m*-of-*n* threshold signature** over the
image hash.

- `compute_pubkey()` (`core/embed/sec/image/image.c:89`) rebuilds the combined
  public key from the header `sigmask`, requiring `popcount(sigmask) == sig_m`
  and `sig_m <= sig_n` (`image.c:92`–`99`); it combines the selected public keys
  with `ed25519_cosi_combine_publickeys` (`image.c:110`).
- `check_image_header_sig()` (`core/embed/sec/image/image.c:178`) verifies the
  signature over the image fingerprint with `ed25519_sign_open(fingerprint,
  IMAGE_HASH_DIGEST_LENGTH, pub, hdr->sig)` (`image.c:189`–`191`), returning
  `sectrue * (0 == …)` so any non-zero result collapses to `secfalse`.
- The chain is staged: boardloader → bootloader → firmware, each verifying the
  next. `boot_image_check()` and the update path use `ensure(check_..._sig(...),
  "...")` (`core/embed/sec/image/stm32/boot_image.c:121`, and
  `check_bootloader_header_sig`).

**On failure:** `ensure(cond, msg)` halts the device via `system_exit_error`
when `cond != sectrue`; unsigned or tampered code is not executed. The header
check also enforces size/layout bounds (`image.c:206`–`219`) and device-model
binding (`check_image_model`, `image.c:140`), and the image version is parsed
(`image.c:562`–`565`) for anti-rollback decisions higher up the stack.

**Assessment:** signature verification is threshold Ed25519 with hardened
boolean results and fatal-halt on failure — robust against unsigned-code
execution. **Unclear from this review:** the exact anti-rollback (version
monotonicity) enforcement and where the root public keys are stored/protected
were not fully traced; I would confirm those before rating downgrade resistance.

---

## B.5 — How does the current design answer the published Trezor One glitch/fault attacks?

| Published attack (Trezor One) | Root cause | Mitigation in current core, with citation | Status |
|---|---|---|---|
| **wallet.fail** (35C3, Dec 2018): voltage glitch bypasses protection; recovered seed/PIN from SRAM because secrets sat in RAM | Secrets in MCU RAM; glitchable boot/readout | Secrets held/bound in a **secure element** (Optiga / Tropic) via `derive_kek_set` → `optiga_pin_stretch_cmac_ecdh`, `tropic_pin_set` with **Mac-and-Destroy** (`storage/storage.c:704`–`740`); RAM secrets `memzero`'d immediately after use (e.g. `storage/storage.c:613`, `1136`); glitch-hardened `sectrue` and fault handler (B.3) | **Addressed** on SE-equipped models |
| **Kraken Security Labs** (2020): voltage glitch dumps encrypted flash, then **offline brute-force of the PIN** (low PIN entropy, on-chip KDF) | KEK derivable from PIN with on-device compute only → off-chip brute force | KEK is **bound to the secure element**: PBKDF2 stretch *then* SE stretch (`optiga_pin_stretch_cmac_ecdh`, `storage.c:705`; `tropic_pin_set_kek_masks`, `storage.c:744`). The SE enforces a hardware attempt counter / Mac-and-Destroy, so the KEK cannot be reconstructed off-chip from dumped flash alone | **Addressed** on SE-equipped models; MCU-only builds rely on PBKDF2 + the wipe counter |
| **Glitch-to-skip PIN check / fault the comparison** | Single fault flips a boolean or skips the compare loop | `sectrue=0xAAAAAAAA` (`secbool.h:25`); loop-completion checks → `handle_fault` (`storage.c:203`,`229`); fail-counter incremented before the check and re-verified (`storage.c:1202`–`1212`); re-entrant fault handler wipes (`storage.c:1816`) | **Addressed** |
| **Timing/SPA on PIN comparison** (the Part A.1 class) | Early-exit byte compare | Constant-time `secequal`, masked `secequal32` (`storage.c:191`,`211`); `wait_random()` desync (`storage.c:1131`) | **Addressed** |
| **Unsigned/rolled-back firmware** | Weak/absent boot verification | Threshold Ed25519 CoSi, fatal-halt on failure (B.4) | **Addressed for signing;** anti-rollback enforcement not fully traced — *flagged* |

**Where the defense is unclear (stated plainly):**

- **MCU-only models without a secure element.** The strongest anti-brute-force
  guarantees above come from Optiga/Tropic. On a build with neither
  (`#if !USE_OPTIGA && !USE_TROPIC`), KEK protection falls back to
  `memcpy(kek, stretched_pins[0], …)` (`storage/storage.c:749`), i.e. PBKDF2 plus
  the software wipe counter. That is weaker against the Kraken-style
  dump-then-brute-force attack, and the strength then rests on PIN entropy and
  PBKDF2 iteration count. This should be evaluated per product.
- **Anti-rollback** version enforcement and root-key storage/protection were not
  fully traced (see B.4).
- **Per-target `secure_aes`** path (software table AES vs SAES peripheral) was
  not verified on every board (see B.2).

**Overall:** the current core firmware shows a deliberate, well-cited answer to
each published Trezor One side-channel/fault attack: constant-time + masked
comparison, glitch-hardened booleans, redundant and loop-checked fault defenses,
secure-element binding of the PIN-derived key, and threshold-signed secure boot.
The residual risks are concentrated in (a) builds lacking a secure element and
(b) areas this source-only review did not fully trace (anti-rollback, per-target
AES).
