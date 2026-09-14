"""Checksum-validated PII detection over extracted text.

Called by both document analyzers via ``analyze_text(text, location, ids)``. Emits a
finding only when a checksum passes (Luhn for cards, Verhoeff for Aadhaar, format for
PAN), so a random 12-digit invoice number does not become a false Aadhaar hit.
EMAIL and PHONE are regex-only (no checksum exists).

Contract: ``analyze_text(text, location, ids) -> tuple[list[Finding], dict[str, str]]``.
Raw values go into the returned secrets dict, never onto a Finding.
"""
from __future__ import annotations

import re

from ..models import Finding, IdGen, mask, sha256_hex

# python-stdnum is optional at import time so the module still loads if the wheel
# failed to install on venue wifi. Missing validators simply disable those types.
try:
    from stdnum import luhn as _luhn
except Exception:  # pragma: no cover
    _luhn = None
try:
    from stdnum.in_ import pan as _pan
except Exception:  # pragma: no cover
    _pan = None
try:
    from stdnum.in_ import aadhaar as _aadhaar
except Exception:  # pragma: no cover
    _aadhaar = None

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Indian mobile: optional +91 / 0 prefix, then 10 digits that MAY contain single
# spaces or hyphens between groups (e.g. "+91 91761 31104", "98765-43210"). The
# candidate is validated by _valid_phone() after normalising, to reject non-phones.
PHONE_RE = re.compile(r"(?<!\d)(?:(?:\+|00)?91[\s\-]?|0)?(?:\d[\s\-]?){9}\d(?!\d)")
# Candidate digit groups for checksum validation.
CARD_RE = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")
AADHAAR_RE = re.compile(r"(?<!\d)\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)")
PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")

ADDRESS_PREFIX_RE = re.compile(
    r"(?i)^(?:address|residing at|residence|location|permanent address|correspondence address|street address|residential address)\s*:\s*([^\n\r]+)$"
)
STREET_ADDRESS_RE = re.compile(
    r"\b(?:\d{1,5}\s+[A-Za-z0-9\.\-\s]{2,35}(?:street|st\.?|road|rd\.?|avenue|ave\.?|boulevard|blvd\.?|drive|dr\.?|lane|ln\.?|way|court|ct\.?|place|pl\.?|highway|hwy\.?|parkway|pkwy\.?|terrace|circle|cir\.?)|(?:p\.?o\.?\s*box\s*\d+|(?:flat|apt\.?|suite|ste\.?|unit|building|block|sector)\s*[\w\-]+))[^\n\r,]{0,40}(?:\s*,\s*[^\n\r,]{2,30}){0,3}(?:\s*,\s*(?:[A-Z]{2}\s+\d{5}(?:-\d{4})?|\b\d{6}\b))?",
    re.IGNORECASE
)
CITY_STATE_ZIP_RE = re.compile(
    r"\b[A-Z][a-zA-Z\s]{2,20}\s*,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?\b"
)
INDIAN_PIN_ADDRESS_RE = re.compile(
    r"\b[A-Z0-9][a-zA-Z0-9\s,\.\-]{5,60}(?:pin(?:\s*code)?|pincode)\s*[:\-]?\s*\b\d{6}\b",
    re.IGNORECASE
)


def _valid_phone(raw: str) -> bool:
    """After stripping separators and an optional +91/0 prefix, an Indian mobile is
    exactly 10 digits starting 6-9."""
    d = re.sub(r"\D", "", raw)
    if len(d) == 12 and d.startswith("91"):
        d = d[2:]
    elif len(d) == 11 and d.startswith("0"):
        d = d[1:]
    return len(d) == 10 and d[0] in "6789"


def _emit(findings, secrets, ids, ftype, location, visibility, severity, raw):
    fid = ids.next()
    findings.append(
        Finding(
            id=fid,
            type=ftype,
            location=location,
            visibility=visibility,
            value_hash=sha256_hex(raw),
            value_preview=mask(raw),
            severity=severity,
        )
    )
    secrets[fid] = raw


def analyze_text(text: str, location: str, ids: IdGen) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    secrets: dict[str, str] = {}
    if not text:
        return findings, secrets

    seen: set[str] = set()  # dedupe identical raw values within one text blob

    def once(raw: str) -> bool:
        if raw in seen:
            return False
        seen.add(raw)
        return True

    for m in EMAIL_RE.finditer(text):
        raw = m.group(0)
        if once(raw):
            _emit(findings, secrets, ids, "EMAIL", location, "visible", "MEDIUM", raw)

    for line in text.splitlines():
        line_clean = line.strip()
        if not line_clean:
            continue
        m_addr = ADDRESS_PREFIX_RE.match(line_clean)
        if m_addr:
            raw = m_addr.group(1).strip()
            if len(raw) >= 5 and once(raw):
                _emit(findings, secrets, ids, "ADDRESS", location, "visible", "HIGH", raw)
        else:
            for m in STREET_ADDRESS_RE.finditer(line_clean):
                raw = m.group(0).strip().rstrip(".,;")
                if len(raw) >= 8 and once(raw):
                    _emit(findings, secrets, ids, "ADDRESS", location, "visible", "HIGH", raw)
            for m in CITY_STATE_ZIP_RE.finditer(line_clean):
                raw = m.group(0).strip()
                if len(raw) >= 8 and once(raw):
                    _emit(findings, secrets, ids, "ADDRESS", location, "visible", "HIGH", raw)
            for m in INDIAN_PIN_ADDRESS_RE.finditer(line_clean):
                raw = m.group(0).strip()
                if len(raw) >= 8 and once(raw):
                    _emit(findings, secrets, ids, "ADDRESS", location, "visible", "HIGH", raw)

    for m in PHONE_RE.finditer(text):
        raw = m.group(0).strip()
        if _valid_phone(raw) and once(raw):
            _emit(findings, secrets, ids, "PHONE", location, "visible", "MEDIUM", raw)

    if _pan is not None:
        for m in PAN_RE.finditer(text):
            raw = m.group(0)
            if _pan.is_valid(raw) and once(raw):
                _emit(findings, secrets, ids, "PAN", location, "visible", "HIGH", raw)

    if _aadhaar is not None:
        for m in AADHAAR_RE.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            if _aadhaar.is_valid(digits) and once(raw):
                _emit(findings, secrets, ids, "AADHAAR", location, "visible", "CRITICAL", raw)

    if _luhn is not None:
        for m in CARD_RE.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            if 13 <= len(digits) <= 19 and _luhn.is_valid(digits) and once(raw):
                _emit(findings, secrets, ids, "CARD", location, "visible", "CRITICAL", raw)

    return findings, secrets


def coverage() -> list:
    # text_pii has no standalone coverage surface; document analyzers own it.
    return []
