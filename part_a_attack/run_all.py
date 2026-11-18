"""Reproduce every Part A result and figure in order.

Run from part_a_attack/:  python run_all.py
Requires data/cwtraces (see ../tools/fetch_reference.py).
"""
import runpy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import a1_spa_password
import a2_cpa_aes
import a3_traces_to_disclosure
import a4_jitter_countermeasure

if __name__ == "__main__":
    print("\n== A.1 SPA password check ==")
    a1_spa_password.main()
    for camp in ("lab4_1", "lab4_2", "lab3_3"):
        print(f"\n== A.2 CPA AES key recovery ({camp}) ==")
        a2_cpa_aes.main(camp)
    for camp in ("lab4_1", "lab4_2"):
        print(f"\n== A.3 traces to disclosure ({camp}) ==")
        a3_traces_to_disclosure.main(camp)
    print("\n== A.4 jitter countermeasure & resync ==")
    a4_jitter_countermeasure.main()
    print("\nAll Part A results written to figures/ and results/.")
