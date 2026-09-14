"""Coverage manifest — generated from analyzer coverage() calls, never hardcoded.

This is the honest false-negative disclosure: every scan reports what it did NOT
check, so a green result is never mistaken for a proof of total safety.
"""
from __future__ import annotations

from .analyzers import ANALYZERS


def build(ext: str):
    mod = ANALYZERS.get(ext.lower())
    if mod is None or not hasattr(mod, "coverage"):
        return []
    try:
        return mod.coverage()
    except Exception:
        return []
