"""Image (JPEG) EXIF analyzer (Pillow + piexif).

Detects: GPS coordinates, camera/software fingerprint, and the embedded EXIF
thumbnail — which survives cropping AND naive EXIF stripping and still shows the
original framing. The thumbnail is demo moment #1, and it is also the strongest
image verifier target: we capture its exact bytes, so the verifier can prove those
exact bytes are gone from the output.
"""
from __future__ import annotations

from ..models import CoverageItem, Finding, IdGen, mask, sha256_hex

try:
    import piexif
except Exception:  # pragma: no cover
    piexif = None


def _emit(findings, secrets, ids, ftype, location, visibility, severity, raw, preview=None):
    fid = ids.next()
    findings.append(
        Finding(
            id=fid,
            type=ftype,
            location=location,
            visibility=visibility,
            value_hash=sha256_hex(raw),
            value_preview=preview if preview is not None else mask(raw),
            severity=severity,
        )
    )
    secrets[fid] = raw


def _to_deg(value, ref) -> float:
    d = value[0][0] / value[0][1]
    m = value[1][0] / value[1][1]
    s = value[2][0] / value[2][1]
    result = d + m / 60.0 + s / 3600.0
    if ref in (b"S", b"W", "S", "W"):
        result = -result
    return result


def analyze(path: str, ids: IdGen) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    secrets: dict[str, str] = {}
    if piexif is None:
        return findings, secrets
    try:
        exif = piexif.load(path)
    except Exception:
        return findings, secrets

    # --- GPS ---
    gps = exif.get("GPS", {})
    if gps and piexif.GPSIFD.GPSLatitude in gps and piexif.GPSIFD.GPSLongitude in gps:
        try:
            lat = _to_deg(gps[piexif.GPSIFD.GPSLatitude], gps.get(piexif.GPSIFD.GPSLatitudeRef, b"N"))
            lon = _to_deg(gps[piexif.GPSIFD.GPSLongitude], gps.get(piexif.GPSIFD.GPSLongitudeRef, b"E"))
            raw = f"{lat:.6f},{lon:.6f}"
            _emit(findings, secrets, ids, "GPS_COORDINATES", "exif:GPS",
                  "hidden", "CRITICAL", raw, preview=f"{lat:.3f}, {lon:.3f} (approx)")
        except Exception:
            pass

    # --- Make / Model / Software fingerprint (ASCII, strong verifier targets) ---
    zeroth = exif.get("0th", {})
    for tag, label in (
        (piexif.ImageIFD.Make, "exif:Make"),
        (piexif.ImageIFD.Model, "exif:Model"),
        (piexif.ImageIFD.Software, "exif:Software"),
    ):
        v = zeroth.get(tag)
        if v:
            raw = v.decode("latin-1", "ignore").rstrip("\x00").strip() if isinstance(v, bytes) else str(v)
            if raw:
                _emit(findings, secrets, ids, "SOFTWARE_FINGERPRINT", label,
                      "hidden", "LOW", raw)

    # --- Embedded thumbnail (exact bytes captured -> strong removal proof) ---
    thumb = exif.get("thumbnail")
    if thumb:
        raw = thumb.decode("latin-1")  # round-trips every byte 0-255
        _emit(findings, secrets, ids, "EXIF_THUMBNAIL", "exif:thumbnail",
              "recoverable", "HIGH", raw,
              preview=f"<embedded JPEG, {len(thumb)} bytes — original framing>")

    return findings, secrets


def coverage() -> list[CoverageItem]:
    return [
        CoverageItem("image.exif_gps", True, "GPS latitude/longitude IFD"),
        CoverageItem("image.exif_fingerprint", True, "Make, Model, Software"),
        CoverageItem("image.exif_thumbnail", True, "embedded thumbnail image"),
        # The compiler re-encodes from pixels, so every ancillary metadata block is
        # dropped whether or not it was individually enumerated.
        CoverageItem("image.xmp", True, "XMP packet removed by full re-encode"),
        CoverageItem("image.icc_profile", True, "ICC colour profile removed by full re-encode"),
        CoverageItem("image.iptc", True, "IPTC metadata removed by full re-encode"),
        CoverageItem("image.steganography", False,
                     "data hidden in pixel values is undetectable by design — no tool can "
                     "verify its absence"),
    ]
