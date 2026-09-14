"""PrivacyLens API. Three routes + static frontend mount.

  POST /analyze            file            -> {session_id, findings[]}
  POST /sanitize           {session_id,intent} -> {findings[], coverage[], download_url, judge}
  GET  /download/{sid}     -                -> the sanitized file

Raw values never enter a response body — findings carry only masked previews and
hashes. The secrets map stays inside storage and the local pipeline.
"""
from __future__ import annotations

import os
import tempfile
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

load_dotenv()  # read .env so GEMINI_API_KEY is available to judge.py

from . import coverage, custom, judge, storage, verifier
from .analyzers import ANALYZERS
from .compiler import COMPILERS
from .models import IdGen, Tokenizer, type_info
from .policy.engine import VALID_INTENTS, apply_overrides, decide

app = FastAPI(title="PrivacyLens")

# Allow the page to call the API even when opened as a local file:// (origin "null").
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")


def _finding_dict(f) -> dict:
    label, desc = type_info(f.type)
    return {
        "id": f.id,
        "type": f.type,
        "type_label": label,
        "type_desc": desc,
        "location": f.location,
        "visibility": f.visibility,
        "value_hash": f.value_hash,
        "value_preview": f.value_preview,   # masked, safe to render
        "severity": f.severity,
        "decision": f.decision,
        "removed": f.removed,
        "note": f.note,
        "meta": {k: v for k, v in f.meta.items() if k in ("page", "rects", "boxes", "part", "ocr")},
    }


def _coverage_dict(c) -> dict:
    return {"category": c.category, "checked": c.checked, "detail": c.detail}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...), intent: str = Form("public_sharing")):
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ANALYZERS:
        raise HTTPException(400, f"Unsupported file type: {ext or '(none)'}")

    suffix = ext
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(await file.read())
    tmp.close()

    ids = IdGen()
    try:
        findings, secrets = ANALYZERS[ext].analyze(tmp.name, ids)
    except Exception as exc:  # fail visibly, not silently
        raise HTTPException(500, f"Analysis failed: {exc}")

    # Replace asterisk-blurred previews with readable, stable pseudonyms
    # (Person 1, Email 2, ...). Raw values stay in the secrets map only.
    tok = Tokenizer()
    for f in findings:
        t = tok.token(f.type, secrets.get(f.id, ""))
        if t:
            f.value_preview = t

    # Seed each finding with a preview decision so the pre-sanitize overlay can colour
    # regions by KEEP/WARN/REMOVE. /sanitize recomputes decisions from the real intent.
    if intent not in VALID_INTENTS:
        intent = "public_sharing"
    decide(findings, intent)

    session_id = storage.create(tmp.name, ext, findings, secrets, name=file.filename or "file")
    return {"session_id": session_id, "findings": [_finding_dict(f) for f in findings]}


class SanitizeRequest(BaseModel):
    session_id: str
    intent: str
    # Optional per-finding manual overrides: {finding_id: "KEEP"|"WARN"|"REMOVE"}.
    # Applied on top of the intent-driven defaults; legal_hold still blocks REMOVE.
    overrides: Optional[dict] = None
    # Redaction style for the output file: "token" ([EMAIL]) or "blackbox" (solid bars).
    style: str = "token"
    # User-supplied items to redact compulsorily (things the tool can't infer).
    custom_terms: Optional[list] = None


@app.post("/sanitize")
async def sanitize(req: SanitizeRequest):
    sess = storage.get(req.session_id)
    if sess is None:
        raise HTTPException(404, "Unknown session_id")
    if req.intent not in VALID_INTENTS:
        raise HTTPException(400, f"Invalid intent. One of: {', '.join(VALID_INTENTS)}")

    ext = sess["ext"]
    style = "blackbox" if req.style == "blackbox" else "token"

    # Build the user's compulsory-redact items fresh each run (ids prefixed "u" so they
    # never collide with the auto-detected "f" ids), then merge with the auto findings.
    cids = IdGen(prefix="u")
    custom_findings, custom_secrets = custom.build(sess["path"], ext, req.custom_terms, cids)
    ctok = Tokenizer()
    for f in custom_findings:
        t = ctok.token(f.type, custom_secrets.get(f.id, ""))
        if t:
            f.value_preview = t

    findings = list(sess["findings"]) + custom_findings
    secrets = {**sess["secrets"], **custom_secrets}

    # 1. DECIDE (intent-driven defaults, then any manual overrides from the review UI)
    decide(findings, req.intent)
    apply_overrides(findings, req.overrides, req.intent)

    # 2. COMPILE -> fresh container
    out_path = COMPILERS[ext].compile(sess["path"], findings, secrets, style)

    # 3. VERIFY (independent, byte-level; OCR findings verified separately by re-OCR)
    verifier.verify(out_path, findings, secrets)
    if ext in (".jpg", ".jpeg", ".png"):
        from .analyzers import image_ocr
        image_ocr.verify_visual(out_path, findings, secrets)

    # 4. COVERAGE (generated)
    cov = coverage.build(ext)
    unchecked = [c.category for c in cov if not c.checked]

    # 5. JUDGE (optional, advisory, escalate-only; offline path is default)
    judge_result = judge.judge(findings, req.intent, unchecked)
    judge.apply_advice(findings, judge_result)

    storage.set_output(req.session_id, out_path, req.intent)

    return {
        "findings": [_finding_dict(f) for f in findings],
        "coverage": [_coverage_dict(c) for c in cov],
        "download_url": f"/download/{req.session_id}",
        "judge": {
            "available": judge_result.get("available", False),
            "coverage_note": judge_result.get("coverage_note", ""),
            "linkage_note": judge_result.get("linkage_note", ""),
        },
    }


@app.get("/download/{session_id}")
async def download(session_id: str):
    sess = storage.get(session_id)
    if sess is None or not sess.get("out_path"):
        raise HTTPException(404, "No sanitized file for this session")
    name = sess.get("name") or "file"
    return FileResponse(sess["out_path"], filename=f"sanitized_{name}")


_MEDIA_TYPES = {".pdf": "application/pdf", ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg", ".png": "image/png"}


@app.get("/preview/{session_id}")
async def preview(session_id: str):
    """Same sanitized bytes as /download, but served INLINE (no filename= => the
    Content-Disposition is inline) so a browser can render it in an iframe/<img>."""
    sess = storage.get(session_id)
    if sess is None or not sess.get("out_path"):
        raise HTTPException(404, "No sanitized file for this session")
    ext = sess.get("ext", "")
    return FileResponse(sess["out_path"], media_type=_MEDIA_TYPES.get(ext, "application/octet-stream"))


def _flat_exif(path: str) -> dict:
    """Flatten readable EXIF tags to {ifd/TagName: value}. Never returns raw thumbnail
    bytes (shown as a size) — and this is metadata, not document PII."""
    try:
        import piexif
    except Exception:
        return {}
    try:
        data = piexif.load(path)
    except Exception:
        return {}
    out = {}
    for ifd in ("0th", "Exif", "GPS", "1st"):
        for tag, val in (data.get(ifd) or {}).items():
            try:
                name = piexif.TAGS[ifd][tag]["name"]
            except Exception:
                name = str(tag)
            if isinstance(val, bytes):
                val = val.decode("latin-1", "ignore").rstrip("\x00")
            out[f"{ifd}/{name}"] = str(val)[:120]
    thumb = data.get("thumbnail")
    if thumb:
        out["thumbnail"] = f"<embedded JPEG, {len(thumb)} bytes>"
    return out


@app.get("/preview/{session_id}/exif")
async def preview_exif(session_id: str):
    """Original vs sanitized EXIF tag tables — the useful before/after for images,
    since GPS/thumbnail removal is invisible in the pixels."""
    sess = storage.get(session_id)
    if sess is None:
        raise HTTPException(404, "Unknown session")
    original = _flat_exif(sess["path"])
    sanitized = _flat_exif(sess["out_path"]) if sess.get("out_path") else {}
    return {"original": original, "sanitized": sanitized}


# Static frontend last, so API routes take precedence.
if os.path.isdir(_FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=_FRONTEND_DIR, html=True), name="frontend")
