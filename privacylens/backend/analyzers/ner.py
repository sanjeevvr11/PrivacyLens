"""Person name detection using spaCy NER, honorifics, and pattern heuristics.

Identifies person names in document text while filtering out common false positives
(job titles, document section headings, address road/street names, and software terms).
"""
from __future__ import annotations

import re

from ..models import Finding, IdGen, mask, sha256_hex

_NLP = None
_TRIED = False

DENYLIST = {
    "curriculum vitae", "resume", "cover letter", "bio data", "work experience",
    "education background", "technical skills", "personal details", "job description",
    "declaration", "references available", "summary", "objective", "certifications",
    "contact information", "project details", "personal information",
    "confidential investigation report", "investigation report", "confidential report",
    "official report", "final report", "annual report", "status report",
}

JOB_TITLE_KEYWORDS = {
    "engineer", "developer", "manager", "architect", "director", "analyst", "lead",
    "administrator", "officer", "specialist", "consultant", "designer", "head", "vp",
    "ceo", "cto", "cfo", "coo", "president", "intern", "trainee", "fellow", "professor",
    "associate", "executive", "curriculum", "vitae", "resume", "summary", "objective",
    "experience", "skills", "education", "declaration", "references", "projects"
}

ADDRESS_KEYWORDS = {
    "street", "st", "road", "rd", "avenue", "ave", "boulevard", "blvd", "drive", "dr",
    "lane", "ln", "way", "court", "ct", "place", "pl", "terrace", "highway", "hwy",
    "parkway", "pkwy", "layout", "nagar", "colony", "sector", "apartment", "apt",
    "suite", "ste", "flat", "building", "block", "residence", "address", "location"
}

HONORIFIC_NAME_RE = re.compile(
    r"\b(?:Mr\.|Mrs\.|Ms\.|Miss|Dr\.|Prof\.|Sir)\s+([A-Z][a-z]+(?:\s+[A-Z]\.?)?(?:\s+[A-Z][a-z]+){1,2})\b"
)

NAME_PREFIX_RE = re.compile(
    r"(?i)^(?:name|candidate name|full name|author|submitted by|contact)\s*:\s*([A-Za-z\.\s]{2,40})$"
)


def _load():
    global _NLP, _TRIED
    if not _TRIED:
        _TRIED = True
        try:
            import spacy
            _NLP = spacy.load("en_core_web_sm")
        except Exception:
            _NLP = None
    return _NLP


def available() -> bool:
    return _load() is not None


def _is_valid_name(val: str) -> bool:
    val = val.strip()
    lval = val.lower()
    if lval in DENYLIST:
        return False
    words = [w.strip(".,;") for w in val.split() if w.strip(".,;")]
    if not (1 <= len(words) <= 4):
        return False
    for w in words:
        lw = w.lower()
        if lw in JOB_TITLE_KEYWORDS or lw in ADDRESS_KEYWORDS:
            return False
        if not re.match(r"^[A-Z][a-zA-Z\.\-]*$", w):
            return False
    return True


def analyze_names(text: str, location: str, ids: IdGen):
    findings: list[Finding] = []
    secrets: dict[str, str] = {}
    if not text:
        return findings, secrets

    candidates: set[str] = set()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    # 1. Field prefixes (e.g., Name: John Doe)
    for line in lines:
        m = NAME_PREFIX_RE.match(line)
        if m:
            raw = m.group(1).strip()
            if _is_valid_name(raw):
                candidates.add(raw)

    # 2. Honorifics (e.g., Dr. Ananya Sharma, Mr. Robert Lee)
    for m in HONORIFIC_NAME_RE.finditer(text):
        raw = m.group(0).split("\n")[0].split("\r")[0].strip()
        candidates.add(raw)

    # 3. Document top-lines heuristic (e.g., Resume author title)
    for line in lines[:6]:
        if _is_valid_name(line):
            candidates.add(line)

    # 4. spaCy NER on whole text
    nlp = _load()
    if nlp:
        try:
            doc = nlp(text[:100000])
            for ent in doc.ents:
                if ent.label_ == "PERSON":
                    raw = ent.text.strip().split("\n")[0].split("\r")[0].strip()
                    if _is_valid_name(raw):
                        candidates.add(raw)
        except Exception:
            pass

    seen: set[str] = set()
    for cand in candidates:
        idx = text.lower().find(cand.lower())
        raw = text[idx:idx + len(cand)] if idx >= 0 else cand
        raw = raw.strip()
        if raw:
            seen.add(raw)

    # Substring deduplication: if "Ananya Sharma" is contained in "Dr. Ananya Sharma", keep the longer one
    sorted_raws = sorted(seen, key=len, reverse=True)
    filtered_raws: list[str] = []
    for r in sorted_raws:
        if not any(r in longer and r != longer for longer in filtered_raws):
            filtered_raws.append(r)

    for raw in filtered_raws:
        fid = ids.next()
        findings.append(
            Finding(
                id=fid,
                type="PERSON_NAME",
                location=location,
                visibility="visible",
                value_hash=sha256_hex(raw),
                value_preview=mask(raw),
                severity="MEDIUM",
            )
        )
        secrets[fid] = raw

    return findings, secrets
