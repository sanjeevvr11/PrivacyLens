"""Optional OCR-based PII detection for raster images (scanned IDs, card photos).

This is the ONE fuzzy, approximate detector in PrivacyLens, and it is treated as
such — optional, off unless Tesseract + pytesseract are present, and NOT covered by
the byte-level verifier (you cannot byte-search a value that lives in pixels). Its
own honest check is a RE-OCR of the sanitized image (see verify_visual): if the
value is no longer legible to OCR, it is marked visually removed.

Pipeline:
  image -> Tesseract word boxes -> reuse text_pii + ner detectors on the OCR text
        -> map each finding back to its word boxes (the region of interest)
        -> compiler black-fills those boxes -> re-OCR confirms it is gone.

Enable with:
    pip install pytesseract         # and the tesseract binary (brew install tesseract)
"""
from __future__ import annotations

import re

from . import ner, text_pii

_OK = None


def available() -> bool:
    global _OK
    if _OK is None:
        try:
            import pytesseract
            pytesseract.get_tesseract_version()
            _OK = True
        except Exception:
            _OK = False
    return _OK


def _norm(s: str) -> str:
    # Strip ALL non-alphanumerics so matching is robust to OCR punctuation/spacing
    # noise (commas in addresses, dots in emails read inconsistently).
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _words(path):
    """Return [{text, box=[x,y,w,h], block, line}] for confident OCR words."""
    import pytesseract
    from pytesseract import Output
    from PIL import Image

    data = pytesseract.image_to_data(Image.open(path), output_type=Output.DICT)
    out = []
    for i in range(len(data["text"])):
        txt = (data["text"][i] or "").strip()
        try:
            conf = float(data["conf"][i])
        except (TypeError, ValueError):
            conf = -1.0
        if txt and conf >= 30:
            out.append({
                "text": txt,
                "box": [int(data["left"][i]), int(data["top"][i]),
                        int(data["width"][i]), int(data["height"][i])],
                "block": data["block_num"][i],
                "line": data["line_num"][i],
            })
    return out


def _full_text(words) -> str:
    parts, prev = [], None
    for w in words:
        key = (w["block"], w["line"])
        if prev is not None and key != prev:
            parts.append("\n")
        parts.append(w["text"])
        prev = key
    return " ".join(parts).replace(" \n ", "\n")


def _boxes_for(value: str, words) -> list:
    """Locate the word boxes that make up `value` (the region of interest)."""
    target = _norm(value)
    if not target:
        return []
    n = len(words)
    for i in range(n):
        acc, boxes = "", []
        for j in range(i, min(i + 30, n)):  # long enough for a full address line
            acc += _norm(words[j]["text"])
            boxes.append(words[j]["box"])
            if acc == target:
                return boxes
            if len(acc) > len(target):
                break
    # fallback: a single word that contains the value (e.g. an email token)
    for w in words:
        if target in _norm(w["text"]):
            return [w["box"]]
    return []


def analyze_image_text(path: str, ids):
    findings, secrets = [], {}
    if not available():
        return findings, secrets
    try:
        words = _words(path)
    except Exception:
        return findings, secrets
    if not words:
        return findings, secrets

    text = _full_text(words)
    tf, ts = text_pii.analyze_text(text, "image:ocr", ids)
    nf, ns = ner.analyze_names(text, "image:ocr", ids)
    all_secrets = {**ts, **ns}

    for f in tf + nf:
        boxes = _boxes_for(all_secrets.get(f.id, ""), words)
        f.location = "image:printed"
        f.meta = {"ocr": True, "boxes": boxes}
        findings.append(f)
        secrets[f.id] = all_secrets.get(f.id, "")
    return findings, secrets


def verify_visual(path: str, findings, secrets) -> None:
    """Re-OCR the SANITIZED image and mark each removed OCR finding as visually gone
    (or still legible). This is the OCR mode's independent check — the byte verifier
    cannot see into pixels."""
    if not available():
        return
    try:
        import pytesseract
        from PIL import Image
        seen = _norm(pytesseract.image_to_string(Image.open(path)))
    except Exception:
        return
    for f in findings:
        if f.decision == "REMOVE" and f.meta.get("ocr"):
            val = _norm(secrets.get(f.id, ""))
            f.removed = bool(val) and val not in seen
