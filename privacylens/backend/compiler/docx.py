"""DOCX compiler. (path, findings, secrets) -> fresh sanitized container.

Structural removals only, plus value-based blanking of body-text PII (using the
local secrets map). Never edits in place — always rebuilds a fresh zip, because an
in-place zip edit leaves the old bytes in the archive with only the central
directory rewritten, which the verifier would (correctly) catch.
"""
from __future__ import annotations

import tempfile

from lxml import etree

from ..analyzers.docx import NS, load_parts, save_parts, _q
from ..models import category_label

CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CUST_NS = "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"

# Comment-related parts that must all go together, with their rel targets.
_COMMENT_PARTS = [
    "word/comments.xml",
    "word/commentsExtended.xml",
    "word/commentsIds.xml",
    "word/commentsExtensible.xml",
    "word/people.xml",
]


def _ser(el) -> bytes:
    return etree.tostring(el, xml_declaration=True, encoding="UTF-8", standalone=True)


def _removals_by_type(findings):
    out: dict[str, list] = {}
    for f in findings:
        if f.decision == "REMOVE":
            out.setdefault(f.type, []).append(f)
    return out


def _set_element_text(part_bytes: bytes, field: str, replacement: str) -> bytes:
    """Replace the text of a docProps element (creator, Application, ...) with a
    pseudonym token (or "" to blank). Keeps the element and the part — only the raw
    value goes."""
    root = etree.fromstring(part_bytes)
    # field is the local name; search across the known metadata namespaces.
    for prefix in ("dc", "cp", "ep", "dcterms"):
        el = root.find(_q(prefix, field))
        if el is not None:
            el.text = replacement
            return _ser(root)
    return part_bytes


def _remove_comment_refs(doc_bytes: bytes) -> bytes:
    root = etree.fromstring(doc_bytes)
    for tag in ("commentRangeStart", "commentRangeEnd", "commentReference"):
        for el in list(root.iter(_q("w", tag))):
            parent = el.getparent()
            if parent is not None:
                parent.remove(el)
    return _ser(root)


def _strip_tracked_changes(doc_bytes: bytes) -> bytes:
    root = etree.fromstring(doc_bytes)
    # Drop deletions entirely.
    for el in list(root.iter(_q("w", "del"))):
        parent = el.getparent()
        if parent is not None:
            parent.remove(el)
    # Unwrap insertions: keep the inner runs, discard the w:ins wrapper.
    for el in list(root.iter(_q("w", "ins"))):
        parent = el.getparent()
        if parent is None:
            continue
        idx = parent.index(el)
        for child in reversed(list(el)):
            parent.insert(idx, child)
        parent.remove(el)
    return _ser(root)


def _replacement(ftype: str, raw: str, style: str) -> str:
    """The string that replaces a removed value, per redaction style.
    token    -> a category label, e.g. [EMAIL]
    blackbox -> solid blocks the width of the value
    """
    if style == "blackbox":
        return "█" * max(3, len(raw))
    return f"[{category_label(ftype)}]"


def _replace_terms(doc_bytes: bytes, items: list[tuple[str, str]], style: str) -> bytes:
    """Replace each raw value in the body text. items = (raw, finding_type)."""
    if not items:
        return doc_bytes
    root = etree.fromstring(doc_bytes)
    for t in root.iter(_q("w", "t")):
        if not t.text:
            continue
        new = t.text
        for raw, ftype in items:
            if raw and raw in new:
                new = new.replace(raw, _replacement(ftype, raw, style))
        t.text = new
    return _ser(root)


def _blank_custom_prop(custom_bytes: bytes, prop_name: str) -> bytes:
    root = etree.fromstring(custom_bytes)
    for prop in root.findall(f"{{{CUST_NS}}}property"):
        if prop.get("name", "") == prop_name:
            for child in prop:  # the vt:* value element(s)
                child.text = ""
    return _ser(root)


def _drop_content_type_overrides(ct_bytes: bytes, part_names: set[str]) -> bytes:
    root = etree.fromstring(ct_bytes)
    for ov in list(root.findall(f"{{{CT_NS}}}Override")):
        pn = ov.get("PartName", "").lstrip("/")
        if pn in part_names:
            root.remove(ov)
    return _ser(root)


def _drop_relationships(rels_bytes: bytes, targets_suffixes: set[str]) -> bytes:
    root = etree.fromstring(rels_bytes)
    for rel in list(root.findall(f"{{{REL_NS}}}Relationship")):
        target = rel.get("Target", "")
        if any(target.endswith(s) for s in targets_suffixes):
            root.remove(rel)
    return _ser(root)


def compile(path: str, findings, secrets: dict | None = None, style: str = "token") -> str:
    secrets = secrets or {}
    parts = load_parts(path)
    removals = _removals_by_type(findings)

    # 1. Metadata (element kept, raw value removed). Authors become a [NAME] label
    #    (token style) or are blanked (blackbox); software fingerprints are blanked.
    author_repl = "" if style == "blackbox" else f"[{category_label('REVISION_AUTHOR')}]"
    for f in removals.get("REVISION_AUTHOR", []):
        part_name, _, field = f.location.partition(":")
        if part_name in parts and field:
            parts[part_name] = _set_element_text(parts[part_name], field, author_repl)
    for f in removals.get("SOFTWARE_FINGERPRINT", []):
        part_name, _, field = f.location.partition(":")
        if part_name in parts and field:
            parts[part_name] = _set_element_text(parts[part_name], field, "")

    # 2. Comment removal — three-part deletion (part + rels + content-type).
    if removals.get("COMMENT"):
        removed_parts = set()
        for cp in _COMMENT_PARTS:
            if cp in parts:
                del parts[cp]
                removed_parts.add(cp)
        if "[Content_Types].xml" in parts and removed_parts:
            parts["[Content_Types].xml"] = _drop_content_type_overrides(
                parts["[Content_Types].xml"], removed_parts)
        if "word/_rels/document.xml.rels" in parts:
            suffixes = {p.split("/")[-1] for p in removed_parts}
            parts["word/_rels/document.xml.rels"] = _drop_relationships(
                parts["word/_rels/document.xml.rels"], suffixes)
        if "word/document.xml" in parts:
            parts["word/document.xml"] = _remove_comment_refs(parts["word/document.xml"])

    # 3. Tracked changes.
    if removals.get("HIDDEN_TEXT") and "word/document.xml" in parts:
        parts["word/document.xml"] = _strip_tracked_changes(parts["word/document.xml"])

    # 4. Embedded objects.
    emb = removals.get("EMBEDDED_OBJECT", [])
    if emb:
        removed_parts = set()
        for f in emb:
            part_name = f.meta.get("part") or f.location
            if part_name in parts:
                del parts[part_name]
                removed_parts.add(part_name)
        if "[Content_Types].xml" in parts and removed_parts:
            parts["[Content_Types].xml"] = _drop_content_type_overrides(
                parts["[Content_Types].xml"], removed_parts)
        if "word/_rels/document.xml.rels" in parts:
            suffixes = {p.split("/")[-1] for p in removed_parts}
            parts["word/_rels/document.xml.rels"] = _drop_relationships(
                parts["word/_rels/document.xml.rels"], suffixes)

    # 5. Body-text PII + user-specified terms -> replaced in whatever part they were
    #    found (document body, headers, footers). f.location is the part name.
    terms_by_part: dict[str, list] = {}
    for ftype in ("EMAIL", "PHONE", "PAN", "AADHAAR", "CARD", "PERSON_NAME", "ADDRESS", "USER_SPECIFIED"):
        for f in removals.get(ftype, []):
            if f.id in secrets:
                terms_by_part.setdefault(f.location, []).append((secrets[f.id], ftype))
    for part_name, items in terms_by_part.items():
        if part_name in parts:
            parts[part_name] = _replace_terms(parts[part_name], items, style)

    # 6. Custom document properties -> blank the value.
    for f in removals.get("CUSTOM_PROPERTY", []):
        if "docProps/custom.xml" in parts:
            parts["docProps/custom.xml"] = _blank_custom_prop(
                parts["docProps/custom.xml"], f.meta.get("custom_prop", ""))

    out = tempfile.NamedTemporaryFile(delete=False, suffix=".docx").name
    return save_parts(parts, out)
