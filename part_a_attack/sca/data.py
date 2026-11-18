"""Loaders for the NewAE SCA101 recorded trace sets (cwtraces 0.2.0).

All capture campaigns were recorded by NewAE on a ChipWhisperer-Lite with the
CWLITEARM target (STM32F303, Cortex-M4), per the generator notebooks in
chipwhisperer-jupyter/courses/sca101/generators. Run tools/fetch_reference.py
first to populate data/cwtraces.
"""
from __future__ import annotations

import io
import pickle
from dataclasses import dataclass
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
SCA101 = ROOT / "data" / "cwtraces" / "sca101"


@dataclass
class TraceSet:
    name: str
    traces: np.ndarray        # (N, S) float
    plaintexts: np.ndarray    # (N, 16) uint8
    key: np.ndarray | None    # (16,) uint8, only used to *score* an attack
    ciphertexts: np.ndarray | None = None


def _require(path: Path) -> Path:
    if not path.exists():
        raise FileNotFoundError(f"{path} missing - run `python tools/fetch_reference.py` first")
    return path


def load_aes(name: str) -> TraceSet:
    """Load an SCA101 AES campaign: 'lab3_3', 'lab4_1', 'lab4_2' or 'lab4_3'."""
    if name == "lab4_3":
        d = SCA101 / "Lab_4_3_data" / "traces"
        stem = "2024.09.17-17.23.08_0"
        traces = np.load(_require(d / f"{stem}traces.npy"))
        pts = np.load(d / f"{stem}textin.npy")
        keys = np.load(d / f"{stem}keylist.npy")
        cts = np.load(d / f"{stem}textout.npy")
        assert (keys == keys[0]).all(), "fixed-key campaign expected"
        return TraceSet(name, traces, pts, keys[0], cts)
    traces = np.load(_require(SCA101 / f"{name}_traces.npy"))
    pts = np.load(SCA101 / f"{name}_textin.npy")
    key_path = SCA101 / f"{name}_key.npy"
    key = np.load(key_path) if key_path.exists() else None
    return TraceSet(name, traces, pts, key)


class _NumpyOnlyUnpickler(pickle.Unpickler):
    """Refuse every global except the three numpy reconstructors the file needs.

    The password trace file is a pickle; loading an arbitrary pickle executes
    code. The file was audited with pickletools and only references these names.
    """
    ALLOWED = {
        ("numpy.core.multiarray", "_reconstruct"),
        ("numpy._core.multiarray", "_reconstruct"),
        ("numpy", "ndarray"),
        ("numpy", "dtype"),
    }

    def find_class(self, module, name):
        if (module, name) not in self.ALLOWED:
            raise pickle.UnpicklingError(f"blocked global {module}.{name}")
        if module == "numpy.core.multiarray":
            module = "numpy._core.multiarray"
        return super().find_class(module, name)


def load_password_traces() -> dict:
    """Return {recorded_prefix: [trace, ...]} for the SCA101 Lab 2.1B password check."""
    raw = _require(SCA101 / "lab2_1b_passwords_full.p").read_bytes()
    return _NumpyOnlyUnpickler(io.BytesIO(raw)).load()
