"""Fetch the third-party material this project analyses.

1. ChipWhisperer recorded traces: the NewAE ``cwtraces`` 0.2.0 wheel from PyPI.
   The wheel is checked against a pinned SHA-256, then only the trace data
   files are unpacked into ``data/cwtraces``. The wheel's Python code is never
   imported or executed.
2. Reference repositories (read-only), shallow-cloned at pinned commits into
   ``reference/``:
     - newaetech/chipwhisperer-jupyter (lab descriptions)
     - trezor/trezor-firmware (Part B source review)

Usage:  python tools/fetch_reference.py [--no-repos]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
REF = ROOT / "reference"

CWTRACES_VERSION = "0.2.0"
CWTRACES_SHA256 = "6aee711c515fe6ad24e3673077c79fb5e5dff9e10825ab617c3b044cded49f01"

REPOS = {
    "chipwhisperer-jupyter": ("https://github.com/newaetech/chipwhisperer-jupyter.git",
                              "52f124c858178d05a0071459c0df4f3b1f325e2b"),
    "trezor-firmware": ("https://github.com/trezor/trezor-firmware.git",
                        "57b905e5355c9454e8677a33e458cf31e661406c"),
}

DATA_SUFFIXES = (".npy", ".p")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_traces() -> None:
    DATA.mkdir(exist_ok=True)
    wheel = DATA / f"cwtraces-{CWTRACES_VERSION}-py3-none-any.whl"
    if not wheel.exists():
        meta = json.load(urllib.request.urlopen(
            f"https://pypi.org/pypi/cwtraces/{CWTRACES_VERSION}/json"))
        url = next(u["url"] for u in meta["urls"] if u["filename"].endswith(".whl"))
        print(f"downloading {url}")
        urllib.request.urlretrieve(url, wheel)
    digest = sha256(wheel)
    if digest != CWTRACES_SHA256:
        wheel.unlink()
        sys.exit(f"SHA-256 mismatch for cwtraces wheel: {digest}")
    out = DATA / "cwtraces"
    with zipfile.ZipFile(wheel) as z:
        for name in z.namelist():
            # Only sca101 data files; skip any code inside the wheel.
            if name.startswith("cwtraces/sca101/") and name.endswith(DATA_SUFFIXES):
                target = out / Path(name).relative_to("cwtraces")
                if ".." in target.parts:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(name))
    print(f"trace data unpacked to {out}")


def fetch_repos() -> None:
    REF.mkdir(exist_ok=True)
    for name, (url, commit) in REPOS.items():
        dest = REF / name
        if not dest.exists():
            subprocess.run(["git", "init", "-q", str(dest)], check=True)
            subprocess.run(["git", "-C", str(dest), "remote", "add", "origin", url], check=True)
        subprocess.run(["git", "-C", str(dest), "fetch", "-q", "--depth", "1", "origin", commit],
                       check=True)
        subprocess.run(["git", "-C", str(dest), "checkout", "-q", commit], check=True)
        print(f"{name} at {commit}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-repos", action="store_true", help="only fetch trace data")
    args = ap.parse_args()
    fetch_traces()
    if not args.no_repos:
        fetch_repos()


if __name__ == "__main__":
    main()
