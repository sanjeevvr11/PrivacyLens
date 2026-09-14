"""Image compiler (Pillow). (path, findings, secrets) -> fresh sanitized image.

Two removals:
  * Metadata — regenerate, do not strip. We decode to pixels and re-encode with no
    EXIF; merely deleting tags leaves the embedded thumbnail recoverable, the exact
    failure this project exists to demonstrate.
  * Printed text (OCR findings) — black-fill the located word boxes on the pixels,
    then re-encode. This is APPROXIMATE (it paints over pixels) and is verified by
    re-OCR, not by the byte verifier.
"""
from __future__ import annotations

import shutil
import tempfile

from PIL import Image, ImageDraw

_IMAGE_TYPES = {"GPS_COORDINATES", "SOFTWARE_FINGERPRINT", "EXIF_THUMBNAIL", "USER_SPECIFIED"}


def compile(path: str, findings, secrets: dict | None = None, style: str = "token") -> str:
    needs_strip = any(f.decision == "REMOVE" and f.type in _IMAGE_TYPES for f in findings)
    ocr_boxes = [b for f in findings
                 if f.decision == "REMOVE" and f.meta.get("ocr")
                 for b in f.meta.get("boxes", [])]

    if not needs_strip and not ocr_boxes:
        # Nothing to remove (e.g. legal_hold): hand back a faithful copy.
        out = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg").name
        shutil.copyfile(path, out)
        return out

    img = Image.open(path)
    img.load()  # force pixel decode before we drop metadata
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")

    if ocr_boxes:
        draw = ImageDraw.Draw(img)
        pad = 2  # cover glyph edges fully
        for x, y, w, h in ocr_boxes:
            draw.rectangle([x - pad, y - pad, x + w + pad, y + h + pad], fill=(0, 0, 0))

    out = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg").name
    # Re-encode from pixels only: no exif, no embedded thumbnail carried over.
    img.save(out, format="JPEG", quality=95, exif=b"")
    return out
