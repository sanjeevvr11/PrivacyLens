"""PDF compiler (PyMuPDF). (path, findings, secrets) -> fresh sanitized PDF.

Clears DocInfo + XMP metadata, deletes annotations, redacts every REMOVE finding
that carries rects (covered text AND body-text PII) so the glyphs are genuinely
gone, and uses doc.scrub() for class-level removals (attached files, JavaScript,
form-field values). save(garbage=4) flattens incremental updates — without it prior
revisions survive and the verifier correctly reports removed=False.
"""
from __future__ import annotations

import tempfile

import fitz

from ..models import category_label


def compile(path: str, findings, secrets: dict | None = None, style: str = "token") -> str:
    doc = fitz.open(path)

    removes = [f for f in findings if f.decision == "REMOVE"]
    has_meta = any(f.type in ("REVISION_AUTHOR", "SOFTWARE_FINGERPRINT") for f in removes)
    remove_comments = any(f.type == "COMMENT" for f in removes)

    if has_meta:
        doc.set_metadata({})
        try:
            doc.del_xml_metadata()
        except Exception:
            pass

    reset_form = any(f.type == "FORM_FIELD" for f in removes)

    # Class-level removals via scrub FIRST — before any redaction. clean_pages then
    # drops a reset field's orphaned appearance stream; if redactions run first,
    # that orphan survives and the verifier (correctly) reports removed=False.
    scrub_flags = {f.meta["scrub"] for f in removes if f.meta.get("scrub")}
    if scrub_flags:
        try:
            doc.scrub(
                attached_files="attached_files" in scrub_flags,
                embedded_files="attached_files" in scrub_flags,
                javascript="javascript" in scrub_flags,
                reset_fields=reset_form,
                clean_pages=reset_form,
                metadata=False, xml_metadata=False, redactions=False,
                remove_links=False, thumbnails=False,
                hidden_text=False, reset_responses=False,
            )
        except Exception:
            pass

    # Redact any REMOVE finding that carries rects (covered text + body PII + user
    # terms), carrying each rect's category label for token-style replacement.
    rects_by_page: dict[int, list] = {}
    for f in removes:
        label = f"[{category_label(f.type)}]"
        for r in f.meta.get("rects", []) or []:
            rects_by_page.setdefault(f.meta.get("page", 0), []).append((fitz.Rect(*r), label))

    for pno, page in enumerate(doc):
        if remove_comments:
            for annot in page.annots() or []:
                page.delete_annot(annot)
        page_rects = rects_by_page.get(pno, [])
        if page_rects:
            for rect, label in page_rects:
                if style == "blackbox":
                    page.add_redact_annot(rect, fill=(0, 0, 0))
                else:
                    page.add_redact_annot(rect, text=label, fill=(0.9, 0.9, 0.9),
                                          text_color=(0, 0, 0), fontsize=8)
            # images=REMOVE so a redacted image is actually deleted, not just covered.
            img_mode = getattr(fitz, "PDF_REDACT_IMAGE_REMOVE", 1)
            try:
                page.apply_redactions(images=img_mode)
            except TypeError:
                page.apply_redactions()

    out = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
    doc.save(out, garbage=4, deflate=True, clean=True)
    doc.close()
    return out
