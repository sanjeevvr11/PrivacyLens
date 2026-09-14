"""Person name detection using spaCy NER, honorifics, and pattern heuristics.

Identifies person names in document text while filtering out common false positives
(job titles, document section headings, address road/street names, software terms, and document keywords).
"""
from __future__ import annotations

import re

from ..models import Finding, IdGen, mask, sha256_hex

_NLP = None
_TRIED = False

DENYLIST_WORDS = {
    "curriculum", "vitae", "resume", "cover", "letter", "bio", "data", "experience",
    "education", "background", "skills", "declaration", "references",
    "objective", "certifications", "confidential", "investigation", "report",
    "official", "annual", "synthetic", "photograph", "photo", "content",
    "demonstrator", "fingerprint", "metadata", "sample", "preview", "test",
    "redaction", "decision", "timestamp", "session", "annexure", "appendix",
    "street", "road", "avenue", "nagar", "colony", "sector", "pincode", "postal",
    "notes", "note", "final", "repeated",
}

JOB_TITLE_KEYWORDS = {
    "engineer", "developer", "manager", "architect", "director", "analyst", "lead",
    "administrator", "officer", "specialist", "consultant", "designer", "head", "vp",
    "ceo", "cto", "cfo", "coo", "president", "intern", "trainee", "fellow", "professor",
    "associate", "executive", "curriculum", "vitae", "resume", "summary", "objective",
    "experience", "skills", "education", "declaration", "references", "projects", "agent",
}

ADDRESS_KEYWORDS = {
    "street", "st", "road", "rd", "avenue", "ave", "boulevard", "blvd", "drive", "dr",
    "lane", "ln", "way", "court", "ct", "place", "pl", "terrace", "highway", "hwy",
    "parkway", "pkwy", "layout", "nagar", "colony", "sector", "apartment", "apt",
    "suite", "ste", "flat", "building", "block", "residence", "address", "location",
    "park", "square", "sq", "cross", "main", "floor",
}

HONORIFICS = r"(?:Mr|Mrs|Ms|Miss|Dr|Prof|Sir|Madam|Shri|Smt|Sri|Kumari|Capt|Major|Col|Hon|Rev|Fr|Lord|Lady)"

HONORIFIC_NAME_RE = re.compile(
    rf"\b{HONORIFICS}\.?\s+([A-Z][a-zA-Z\.\'\-]+(?:\s+[A-Z][a-zA-Z\.\'\-]+){{1,3}})\b"
)

FIELD_PREFIX_RE = re.compile(
    r"(?i)\b(?:name|candidate(?:\s*name)?|full\s*name|author|submitted\s*by|contact(?:\s*person)?|informant(?:\s*name)?|subject(?:\s*informant\s*name)?)\s*[:\-–—]\s*([A-Z][a-zA-Z\.\'\-]+(?:\s+[A-Z][a-zA-Z\.\'\-]+){0,3})"
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


def _is_valid_name(val: str, min_words: int = 1) -> bool:
    val = val.strip().strip(".,;:-")
    if not val or "\n" in val or "\r" in val:
        return False
    words = [w.strip(".,;:-\"'()[]") for w in val.split() if w.strip(".,;:-\"'()[]")]
    if not (min_words <= len(words) <= 4):
        return False
    for w in words:
        lw = w.lower()
        if lw in DENYLIST_WORDS or lw in JOB_TITLE_KEYWORDS or lw in ADDRESS_KEYWORDS:
            return False
        # Each word must start with an uppercase letter or initial
        if not re.match(r"^[A-Z][a-zA-Z\.\'\-]*$", w):
            return False
    return True


def analyze_names(text: str, location: str, ids: IdGen):
    findings: list[Finding] = []
    secrets: dict[str, str] = {}
    if not text:
        return findings, secrets

    candidates: set[str] = set()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    # 1. Field prefixes (e.g., Name: John Doe, Candidate: Aarav Krishnan)
    for m in FIELD_PREFIX_RE.finditer(text):
        raw = m.group(1).strip().split("\n")[0].split("\r")[0].strip()
        if _is_valid_name(raw, min_words=1):
            candidates.add(raw)

    # 2. Honorifics (e.g., Dr. Ananya Sharma, Shri Aarav Krishnan)
    for m in HONORIFIC_NAME_RE.finditer(text):
        raw = m.group(0).strip().split("\n")[0].split("\r")[0].strip()
        name_part = m.group(1).strip().split("\n")[0].split("\r")[0].strip()
        if _is_valid_name(name_part, min_words=1):
            candidates.add(raw)

    # 3. Delimited segments in structured lines (e.g., 'Test line 1: Aarav Krishnan --- 62 Lakeview...')
    for line in lines:
        parts = re.split(r"\s*(?:---|–|—|\||\t|\s-\s)\s*", line)
        for p in parts:
            p = p.strip()
            # Strip leading line prefixes like 'Test line 1:', '1.', 'Item 2:'
            p_clean = re.sub(r"(?i)^(?:test\s*line\s*\d*|testline\s*\d*|line\s*\d*|item\s*\d*|\d+[\.\)])\s*[:\-–—]?\s*", "", p).strip()
            if _is_valid_name(p_clean, min_words=2):
                candidates.add(p_clean)

    # 4. Top lines heuristic (for resumes/letters, e.g. first 3 lines)
    for line in lines[:3]:
        first_part = re.split(r"\s*[\-–—\|]\s*", line)[0].strip()
        if _is_valid_name(first_part, min_words=2):
            candidates.add(first_part)

    # 5. spaCy NER on whole text
    nlp = _load()
    if nlp:
        try:
            doc = nlp(text[:100000])
            for ent in doc.ents:
                raw = ent.text.strip().split("\n")[0].split("\r")[0].strip()
                if ent.label_ == "PERSON":
                    if _is_valid_name(raw, min_words=1):
                        candidates.add(raw)
                elif ent.label_ in ("GPE", "ORG"):
                    # Catch names misclassified as GPE/ORG by small statistical models
                    if _is_valid_name(raw, min_words=2):
                        candidates.add(raw)
        except Exception:
            pass

    seen: set[str] = set()
    for cand in candidates:
        cand_clean = cand.split("\n")[0].split("\r")[0].strip()
        idx = text.lower().find(cand_clean.lower())
        raw = text[idx:idx + len(cand_clean)] if idx >= 0 else cand_clean
        raw = raw.strip()
        if raw and _is_valid_name(raw, min_words=1):
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
