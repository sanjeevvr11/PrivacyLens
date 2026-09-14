"""PDF structural analyzer (PyMuPDF / fitz).

Detects: DocInfo + XMP metadata, annotations (comments), COVERED_TEXT (text under an
opaque dark rectangle), body-text PII, embedded/attached files, document-level
JavaScript, and AcroForm field values. Rects for removable text sit in
finding.meta["rects"]; class-level removals (attachments, JS, form fields) carry a
finding.meta["scrub"] flag the compiler maps to doc.scrub().
"""
from __future__ import annotations

import fitz  # PyMuPDF

from ..models import CoverageItem, Finding, IdGen, mask, sha256_hex
from . import ner, text_pii

_DARK_LUM = 0.30
_COVER_FRAC = 0.60


def _emit(findings, secrets, ids, ftype, location, visibility, severity, raw, meta=None):
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
            meta=meta or {},
        )
    )
    secrets[fid] = raw


def _luminance(fill) -> float:
    if not fill:
        return 1.0
    try:
        r, g, b = fill[0], fill[1], fill[2]
    except (TypeError, IndexError):
        return 1.0
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _overlap_frac(word_rect: fitz.Rect, dark: fitz.Rect) -> float:
    inter = word_rect & dark
    wa = word_rect.get_area()
    return inter.get_area() / wa if wa > 0 else 0.0


def _locate(page, text: str) -> list:
    """Rects for a target string. Falls back to word boxes when search_for finds
    nothing (split text runs), so redaction still has something to cover."""
    try:
        rects = [[r.x0, r.y0, r.x1, r.y1] for r in page.search_for(text)]
    except Exception:
        rects = []
    if rects:
        return rects
    try:
        words = page.get_text("words")
    except Exception:
        return []
    out = []
    for w in words:
        token = w[4]
        if token and (token == text or (len(token) >= 4 and (token in text or text in token))):
            out.append([w[0], w[1], w[2], w[3]])
    return out


def _extract_js(doc) -> str:
    """Best-effort: collect document-level JavaScript source from the object table."""
    chunks = []
    try:
        for xref in range(1, doc.xref_length()):
            try:
                obj = doc.xref_object(xref, compressed=True)
            except Exception:
                continue
            if "/JavaScript" in obj or "/JS" in obj:
                try:
                    stream = doc.xref_stream(xref)
                    if stream:
                        chunks.append(stream.decode("latin-1", "ignore"))
                except Exception:
                    pass
    except Exception:
        pass
    return "\n".join(chunks).strip()


def analyze(path: str, ids: IdGen) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    secrets: dict[str, str] = {}
    doc = fitz.open(path)

    # --- DocInfo metadata ---
    meta = doc.metadata or {}
    if (meta.get("author") or "").strip():
        _emit(findings, secrets, ids, "REVISION_AUTHOR", "pdf:DocInfo/Author",
              "hidden", "MEDIUM", meta["author"].strip())
    for key in ("creator", "producer"):
        if (meta.get(key) or "").strip():
            _emit(findings, secrets, ids, "SOFTWARE_FINGERPRINT", f"pdf:DocInfo/{key.title()}",
                  "hidden", "LOW", meta[key].strip())

    # --- XMP metadata ---
    try:
        xmp = doc.xml_metadata()
    except Exception:
        xmp = ""
    if xmp and xmp.strip():
        _emit(findings, secrets, ids, "SOFTWARE_FINGERPRINT", "pdf:XMP",
              "hidden", "LOW", xmp.strip())

    # --- embedded / attached files ---
    try:
        embnames = list(doc.embfile_names())
    except Exception:
        embnames = []
    for nm in embnames:
        _emit(findings, secrets, ids, "EMBEDDED_OBJECT", f"pdf:embfile/{nm}",
              "recoverable", "HIGH", nm, meta={"scrub": "attached_files"})

    # --- document-level JavaScript ---
    js = _extract_js(doc)
    if js:
        _emit(findings, secrets, ids, "JAVASCRIPT", "pdf:catalog/Names/JavaScript",
              "hidden", "HIGH", js, meta={"scrub": "javascript"})

    # --- per-page: annotations, covered text, body PII, form fields ---
    for pno, page in enumerate(doc):
        for annot in page.annots() or []:
            info = annot.info or {}
            content = (info.get("content") or "").strip()
            author = (info.get("title") or "").strip()
            raw = (f"{author}: " if author else "") + content
            if raw.strip():
                _emit(findings, secrets, ids, "COMMENT", f"pdf:page{pno + 1}/annot",
                      "hidden", "MEDIUM", raw)

        # covered text under dark rectangles
        dark_rects = []
        for d in page.get_drawings():
            fill = d.get("fill")
            if fill is not None and _luminance(fill) <= _DARK_LUM:
                r = d.get("rect")
                if r is not None and r.get_area() > 4:
                    dark_rects.append(fitz.Rect(r))
        words = page.get_text("words") if dark_rects else []
        for dark in dark_rects:
            covered = [w[4] for w in words
                       if _overlap_frac(fitz.Rect(w[:4]), dark) >= _COVER_FRAC]
            raw = " ".join(covered).strip()
            if raw:
                _emit(findings, secrets, ids, "COVERED_TEXT", f"pdf:page{pno + 1}/covered",
                      "recoverable", "CRITICAL", raw,
                      meta={"page": pno, "rects": [[dark.x0, dark.y0, dark.x1, dark.y1]]})

        # body-text PII, with rects located for redaction
        text = page.get_text()
        pf, ps = text_pii.analyze_text(text, f"pdf:page{pno + 1}", ids)
        for f in pf:
            f.meta = {"page": pno, "rects": _locate(page, ps.get(f.id, ""))}
        findings.extend(pf)
        secrets.update(ps)

        # optional person-name detection (spaCy NER), WARN-only
        nf, nsec = ner.analyze_names(text, f"pdf:page{pno + 1}", ids)
        for f in nf:
            f.meta = {"page": pno, "rects": _locate(page, nsec.get(f.id, ""))}
        findings.extend(nf)
        secrets.update(nsec)

        # embedded raster images (kept by default — user decides via WARN)
        seen_img = set()
        for img in page.get_images(full=True):
            xref = img[0]
            if xref in seen_img:
                continue
            seen_img.add(xref)
            try:
                rects = [[r.x0, r.y0, r.x1, r.y1] for r in page.get_image_rects(xref)]
            except Exception:
                rects = []
            try:
                data = doc.extract_image(xref).get("image", b"")
            except Exception:
                data = b""
            raw = data.decode("latin-1") if data else f"pdf-image-{xref}"
            fid = ids.next()
            findings.append(
                Finding(
                    id=fid, type="EMBEDDED_IMAGE", location=f"pdf:page{pno + 1}/image",
                    visibility="visible", value_hash=sha256_hex(raw),
                    value_preview=f"<image {img[2]}x{img[3]}px>", severity="LOW",
                    meta={"page": pno, "rects": rects},
                )
            )
            secrets[fid] = raw

        # AcroForm field values
        try:
            widgets = list(page.widgets() or [])
        except Exception:
            widgets = []
        for w in widgets:
            val = w.field_value
            val = val.strip() if isinstance(val, str) else (str(val) if val else "")
            if val:
                _emit(findings, secrets, ids, "FORM_FIELD",
                      f"pdf:page{pno + 1}/field:{w.field_name or '?'}",
                      "visible", "MEDIUM", val, meta={"scrub": "reset_fields"})

    doc.close()
    return findings, secrets


def coverage() -> list[CoverageItem]:
    return [
        CoverageItem("pdf.docinfo_metadata", True, "Author, Creator, Producer"),
        CoverageItem("pdf.xmp_metadata", True, "XMP packet"),
        CoverageItem("pdf.annotations", True, "comment / popup annotations"),
        CoverageItem("pdf.covered_text", True, "text under opaque dark rectangles"),
        CoverageItem("pdf.body_text_pii", True, "checksum-validated PII in page text"),
        CoverageItem("pdf.embedded_files", True, "attached / embedded files"),
        CoverageItem("pdf.javascript", True, "document-level JavaScript"),
        CoverageItem("pdf.form_fields", True, "AcroForm field values"),
        CoverageItem("pdf.embedded_images", True, "embedded raster images (flagged; kept unless you remove them)"),
        CoverageItem("pdf.person_names", ner.available(),
                     "person names via NER" if ner.available()
                     else "person-name detection off — run: pip install spacy && python -m spacy download en_core_web_sm"),
    ]
