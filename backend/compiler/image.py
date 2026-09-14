"""Image compiler (Pillow). (path, findings, secrets) -> fresh sanitized image.

Regenerate, do not strip. We decode to pixels and re-encode to a brand-new file
with no EXIF. Copying original bytes forward and merely deleting tags leaves the
embedded thumbnail recoverable — the exact failure this whole project exists to
demonstrate. Regeneration is all-or-nothing: any REMOVE image finding drops the
entire EXIF block (GPS, fingerprint, thumbnail) at once.
"""
from __future__ import annotations

import shutil
import tempfile

from PIL import Image

_IMAGE_TYPES = {"GPS_COORDINATES", "SOFTWARE_FINGERPRINT", "EXIF_THUMBNAIL", "USER_SPECIFIED"}


def compile(path: str, findings, secrets: dict | None = None, style: str = "token") -> str:
    # style does not apply to images here: metadata is removed by re-encode, not
    # redacted in place (we do not blur pixel regions).
    needs_strip = any(f.decision == "REMOVE" and f.type in _IMAGE_TYPES for f in findings)

    if not needs_strip:
        # Nothing to remove (e.g. legal_hold): hand back a faithful copy.
        out = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg").name
        shutil.copyfile(path, out)
        return out

    img = Image.open(path)
    img.load()  # force pixel decode before we drop metadata
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    out = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg").name
    # Re-encode from pixels only: no exif, no embedded thumbnail carried over.
    img.save(out, format="JPEG", quality=95, exif=b"")
    return out
