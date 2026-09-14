"""Independent, format-ignorant removal verifier — the entire pitch.

It shares NO imports with any analyzer and NO format library. It sees only output
bytes and the local secrets map. For every REMOVE finding it asks one factual
question: does the raw value (or its sha256) still appear anywhere in the output —
inside the zip parts, inside decompressed streams, or in the raw bytes?

A detector's blind spot cannot hide here, because this code makes none of the
detector's assumptions. If you ever find yourself importing lxml or fitz into this
file, stop — you have destroyed the novelty claim.

Known limitation (kept in the report, not hidden): a removed value that also
legitimately appears elsewhere in the file reports removed=False even though removal
worked. That is a property of byte-search independence, not a bug.
"""
from __future__ import annotations

import hashlib
import zipfile
import zlib

# Cap on zlib-header probe attempts, so a large non-zip file can't wedge the scan.
_MAX_STREAM_PROBES = 200_000


def _decompressed_streams(raw: bytes) -> list[bytes]:
    """Best-effort: find zlib streams (e.g. PDF FlateDecode) and decompress them."""
    out: list[bytes] = []
    n = len(raw)
    probes = 0
    i = 0
    while i < n - 1 and probes < _MAX_STREAM_PROBES:
        if raw[i] == 0x78 and raw[i + 1] in (0x01, 0x9C, 0xDA, 0x5E):
            probes += 1
            try:
                d = zlib.decompressobj()
                res = d.decompress(raw[i:])
                if res:
                    out.append(res)
            except Exception:
                pass
        i += 1
    return out


def _needles(raw_val: str) -> list[bytes]:
    needles: list[bytes] = []
    for enc in ("utf-8", "latin-1"):
        try:
            needles.append(raw_val.encode(enc))
        except Exception:
            pass
    needles.append(hashlib.sha256(raw_val.encode("utf-8")).hexdigest().encode())
    return needles


def verify(path: str, findings, secrets: dict):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            blobs = [z.read(n) for n in z.namelist()]
    else:
        raw = open(path, "rb").read()
        blobs = [raw] + _decompressed_streams(raw)
    hay = b"\n".join(blobs)

    for f in findings:
        if f.decision != "REMOVE":
            continue
        if f.meta.get("ocr"):
            continue  # OCR/pixel findings are verified by re-OCR, not byte search
        raw_val = secrets.get(f.id)
        if raw_val is None:
            f.removed = None
            continue
        present = any(needle and needle in hay for needle in _needles(raw_val))
        f.removed = not present
    return findings
