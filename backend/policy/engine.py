"""Policy engine. Pure function: decide(findings, intent) -> findings (decision set).

Two hard-coded overrides live in CODE, not YAML, because a mistyped matrix cell
must never be able to cause a leak or spoliation:

  (a) legal_hold forces any REMOVE -> KEEP   (stripping a document under litigation
      hold is spoliation — invariant §9.4)
  (b) an unknown (type, intent) -> WARN, never KEEP  (fail toward more privacy)
"""
from __future__ import annotations

import os

import yaml

VALID_INTENTS = ("job_application", "public_sharing", "internal_sharing", "legal_hold")

_MATRIX: dict | None = None


def _load_matrix() -> dict:
    global _MATRIX
    if _MATRIX is None:
        matrix_path = os.path.join(os.path.dirname(__file__), "matrix.yaml")
        with open(matrix_path) as fh:
            _MATRIX = yaml.safe_load(fh) or {}
    return _MATRIX


def decide(findings, intent: str):
    matrix = _load_matrix()
    for f in findings:
        action = matrix.get(f.type, {}).get(intent)
        if action not in ("KEEP", "WARN", "REMOVE"):
            action = "WARN"  # override (b): unknown -> WARN, never KEEP
        if intent == "legal_hold" and action == "REMOVE":
            action = "KEEP"  # override (a): legal hold blocks removal
        f.decision = action
    return findings


def apply_overrides(findings, overrides, intent):
    """Apply the reviewer's manual KEEP/WARN/REMOVE choices on top of the defaults.

    legal_hold still wins: a manual REMOVE under legal hold is clamped back to KEEP,
    so the review UI can never be used to cause spoliation (invariant §9.4).
    """
    if not overrides:
        return findings
    for f in findings:
        choice = overrides.get(f.id)
        if choice in ("KEEP", "WARN", "REMOVE"):
            f.decision = choice
    if intent == "legal_hold":
        for f in findings:
            if f.decision == "REMOVE":
                f.decision = "KEEP"
    return findings
