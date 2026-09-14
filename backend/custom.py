"""User-specified sensitive items -> USER_SPECIFIED findings.

The user types things PrivacyLens cannot infer (a project codename, a home address,
a specific name). Each becomes a compulsory-REMOVE finding located in the file, so
the compiler strips it and the verifier proves it gone. Anything the user misses is
still caught by the automatic analyzers.

Format-aware location so removal uses the right mechanism:
  PDF  -> rects via page.search_for  (redacted)
  DOCX -> the text part it appears in (value replaced)
  IMG  -> presence in metadata bytes (removed by full re-encode)
"""
from __future__ import annotations

from .models import Finding, IdGen, mask, sha256_hex


def _mk(fid, location, visibility, raw, meta=None) -> Finding:
    return Finding(
        id=fid,
        type="USER_SPECIFIED",
        location=location,
        visibility=visibility,
        value_hash=sha256_hex(raw),
        value_preview=mask(raw),
        severity="HIGH",
        meta=meta or {},
    )


def _pdf(path, terms, ids):
    import fitz

    findings, secrets = [], {}
    doc = fitz.open(path)
    for term in terms:
        rects_by_page: dict[int, list] = {}
        for pno, page in enumerate(doc):
            for r in page.search_for(term):
                rects_by_page.setdefault(pno, []).append([r.x0, r.y0, r.x1, r.y1])
        if rects_by_page:
            for pno, rects in rects_by_page.items():
                fid = ids.next()
                findings.append(_mk(fid, f"pdf:page{pno + 1}/user", "visible", term,
                                    meta={"page": pno, "rects": rects}))
                secrets[fid] = term
        else:
            # Not found as extractable text — still track it; the verifier will say
            # whether it is genuinely absent or hiding somewhere we cannot redact.
            fid = ids.next()
            findings.append(_mk(fid, "pdf:document/user", "recoverable", term))
            secrets[fid] = term
    doc.close()
    return findings, secrets


def _docx(path, terms, ids):
    from lxml import etree

    from .analyzers.docx import NS, _HDR_FTR_RE, _q, load_parts

    findings, secrets = [], {}
    parts = load_parts(path)
    text_parts = [n for n in parts
                  if n == "word/document.xml" or _HDR_FTR_RE.match(n)]
    for term in terms:
        placed = False
        for n in text_parts:
            root = etree.fromstring(parts[n])
            text = "".join(t.text or "" for t in root.iter(_q("w", "t")))
            if term in text:
                fid = ids.next()
                findings.append(_mk(fid, n, "visible", term))
                secrets[fid] = term
                placed = True
        if not placed:
            fid = ids.next()
            findings.append(_mk(fid, "word/document.xml", "recoverable", term))
            secrets[fid] = term
    return findings, secrets


def _image(path, terms, ids):
    findings, secrets = [], {}
    raw = open(path, "rb").read()

    # Prefer OCR: locate the term in the PIXELS so it can be blacked out and re-OCR
    # verified. Fall back to metadata-byte presence only if OCR can't place it.
    from .analyzers import image_ocr
    words = None
    if image_ocr.available():
        try:
            words = image_ocr._words(path)
        except Exception:
            words = None

    for term in terms:
        boxes = image_ocr._boxes_for(term, words) if words else []
        fid = ids.next()
        if boxes:
            findings.append(_mk(fid, "image:printed", "visible", term,
                                meta={"ocr": True, "boxes": boxes}))
        else:
            present = term.encode("utf-8") in raw or term.encode("latin-1", "ignore") in raw
            findings.append(_mk(fid, "image:metadata", "recoverable" if present else "hidden", term))
        secrets[fid] = term
    return findings, secrets


def build(path: str, ext: str, terms, ids: IdGen):
    terms = [t.strip() for t in (terms or []) if t and t.strip()]
    if not terms:
        return [], {}
    ext = ext.lower()
    if ext == ".pdf":
        return _pdf(path, terms, ids)
    if ext == ".docx":
        return _docx(path, terms, ids)
    if ext in (".jpg", ".jpeg", ".png"):
        return _image(path, terms, ids)
    return [], {}
