"""DOCX structural analyzer.

Analyze and compile share one part map — the zip is loaded once via ``load_parts``
and written back via ``save_parts`` (a fresh container, never an in-place edit).

Detects: revision authorship + software fingerprint (docProps), comments, tracked
changes (w:ins / w:del), embedded objects, and body-text PII (delegated to
``text_pii.analyze_text``).
"""
from __future__ import annotations

import re
from zipfile import ZipFile, ZIP_DEFLATED

from lxml import etree

from ..models import CoverageItem, Finding, IdGen, mask, sha256_hex
from . import ner, text_pii

# Namespace map defined once — lxml namespace errors are a top time sink.
NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "cust": "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties",
}

_HDR_FTR_RE = re.compile(r"word/(header|footer)\d+\.xml$")


def _q(prefix: str, tag: str) -> str:
    return f"{{{NS[prefix]}}}{tag}"


def load_parts(path: str) -> dict[str, bytes]:
    with ZipFile(path) as z:
        return {n: z.read(n) for n in z.namelist()}


def save_parts(parts: dict[str, bytes], out: str) -> str:
    with ZipFile(out, "w", ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    return out


def _text_of(elem) -> str:
    """Concatenate all w:t / w:delText descendants of an element."""
    chunks = []
    for t in elem.iter(_q("w", "t"), _q("w", "delText")):
        if t.text:
            chunks.append(t.text)
    return "".join(chunks)


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


def analyze(path: str, ids: IdGen) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    secrets: dict[str, str] = {}
    parts = load_parts(path)

    # --- docProps/core.xml : creator, lastModifiedBy -> REVISION_AUTHOR ---
    if "docProps/core.xml" in parts:
        core = etree.fromstring(parts["docProps/core.xml"])
        for tag, label in (
            (_q("dc", "creator"), "docProps/core.xml:creator"),
            (_q("cp", "lastModifiedBy"), "docProps/core.xml:lastModifiedBy"),
        ):
            el = core.find(tag)
            if el is not None and (el.text or "").strip():
                _emit(findings, secrets, ids, "REVISION_AUTHOR", label,
                      "hidden", "MEDIUM", el.text.strip())

    # --- docProps/app.xml : Application, Company -> SOFTWARE_FINGERPRINT ---
    if "docProps/app.xml" in parts:
        app = etree.fromstring(parts["docProps/app.xml"])
        for tag, label in (
            (_q("ep", "Application"), "docProps/app.xml:Application"),
            (_q("ep", "Company"), "docProps/app.xml:Company"),
        ):
            el = app.find(tag)
            if el is not None and (el.text or "").strip():
                _emit(findings, secrets, ids, "SOFTWARE_FINGERPRINT", label,
                      "hidden", "LOW", el.text.strip())

    # --- word/comments.xml -> COMMENT (hidden) ---
    if "word/comments.xml" in parts:
        comments = etree.fromstring(parts["word/comments.xml"])
        for c in comments.findall(_q("w", "comment")):
            author = c.get(_q("w", "author"), "")
            body = _text_of(c).strip()
            raw = (f"{author}: " if author else "") + body
            if raw.strip():
                _emit(findings, secrets, ids, "COMMENT",
                      "word/comments.xml:comment", "hidden", "MEDIUM", raw)

    # --- word/document.xml : tracked changes + body-text PII ---
    if "word/document.xml" in parts:
        doc = etree.fromstring(parts["word/document.xml"])
        # Only DELETED text (w:del) is genuinely hidden-and-recoverable: it is invisible
        # on screen yet present in the file. An INSERTION's text is real content that
        # flattening keeps, so it is not reported as removable hidden text — the compiler
        # still strips the revision metadata around it.
        for rev in doc.iter(_q("w", "del")):
            raw = _text_of(rev).strip()
            if raw:
                _emit(findings, secrets, ids, "HIDDEN_TEXT",
                      "word/document.xml:deletion", "recoverable", "HIGH", raw)
        # Body PII over VISIBLE text, joined per-paragraph so a regex cannot run past a
        # paragraph boundary into the next one.
        paras = ["".join(t.text or "" for t in p.iter(_q("w", "t")))
                 for p in doc.iter(_q("w", "p"))]
        body_text = "\n".join(paras)
        tf, ts = text_pii.analyze_text(body_text, "word/document.xml", ids)
        findings.extend(tf)
        secrets.update(ts)
        # optional person-name detection (spaCy NER), WARN-only
        nf, nsec = ner.analyze_names(body_text, "word/document.xml", ids)
        findings.extend(nf)
        secrets.update(nsec)

    # --- word/embeddings/* -> EMBEDDED_OBJECT ---
    for name in parts:
        if name.startswith("word/embeddings/"):
            _emit(findings, secrets, ids, "EMBEDDED_OBJECT", name,
                  "recoverable", "HIGH", name, meta={"part": name})

    # --- headers / footers : body-text PII (same visible-text extraction) ---
    for name in parts:
        if _HDR_FTR_RE.match(name):
            hroot = etree.fromstring(parts[name])
            htext = "\n".join("".join(t.text or "" for t in p.iter(_q("w", "t")))
                              for p in hroot.iter(_q("w", "p")))
            hf, hs = text_pii.analyze_text(htext, name, ids)
            findings.extend(hf)
            secrets.update(hs)

    # --- docProps/custom.xml -> CUSTOM_PROPERTY ---
    if "docProps/custom.xml" in parts:
        croot = etree.fromstring(parts["docProps/custom.xml"])
        for prop in croot.findall(_q("cust", "property")):
            pname = prop.get("name", "")
            val = "".join((v.text or "") for v in prop.iter() if v is not prop).strip()
            if val:
                _emit(findings, secrets, ids, "CUSTOM_PROPERTY",
                      f"docProps/custom.xml:{pname}", "hidden", "LOW", val,
                      meta={"custom_prop": pname})

    return findings, secrets


def coverage() -> list[CoverageItem]:
    return [
        CoverageItem("docx.core_app_metadata", True, "creator, lastModifiedBy, Application, Company"),
        CoverageItem("docx.comments", True, "word/comments.xml"),
        CoverageItem("docx.tracked_changes", True, "w:ins / w:del in document.xml"),
        CoverageItem("docx.embedded_objects", True, "word/embeddings/*"),
        CoverageItem("docx.body_text_pii", True, "checksum-validated PII in document body"),
        CoverageItem("docx.person_names", ner.available(),
                     "person names via NER" if ner.available()
                     else "person-name detection off — run: pip install spacy && python -m spacy download en_core_web_sm"),
        CoverageItem("docx.headers_footers", True, "checksum-validated PII in headers/footers"),
        CoverageItem("docx.custom_doc_properties", True, "docProps/custom.xml values"),
        CoverageItem("docx.custom_xml", False,
                     "customXml/* data islands not removed — deleting them safely without "
                     "corrupting the document is out of scope for this build"),
        CoverageItem("docx.embedded_fonts", False,
                     "embedded font subsets not inspected (not a text-PII vector we rewrite)"),
    ]
