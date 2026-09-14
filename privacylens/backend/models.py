"""PrivacyLens data contract.

This module is THE CONTRACT. Every analyzer returns ``(list[Finding], dict[str, str])``
where the dict maps finding-id -> raw value (the local-only secrets map). Every
compiler takes ``(path, findings_with_decisions) -> out_path``.

Raw values NEVER live on a Finding. They live only in the secrets map, which never
enters a response body and never leaves the process. See invariants §9.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Literal, Optional

Action = Literal["KEEP", "WARN", "REMOVE"]
Visibility = Literal["visible", "hidden", "recoverable"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def sha256_hex(value: str) -> str:
    """Stable hex digest of a raw value. Used as ``Finding.value_hash`` and by the
    verifier to search output bytes for ``sha256(value)`` when a raw compare fails."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def mask(value: str) -> str:
    """Return a render-safe preview of a raw value.

    "John Smith"      -> "J*** S****"
    "jane@corp.com"    -> "j***@corp.com"
    "9876543210"       -> "9********0"
    """
    value = (value or "").strip()
    if not value:
        return ""
    if "@" in value and " " not in value:
        name, _, domain = value.partition("@")
        masked_name = (name[0] + "*" * (len(name) - 1)) if name else ""
        return f"{masked_name}@{domain}"
    parts = value.split()
    if len(parts) > 1:
        return " ".join((p[0] + "*" * (len(p) - 1)) if p else p for p in parts)
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


# Category label written into the output in "token" redaction style, e.g. [EMAIL].
CATEGORY = {
    "EMAIL": "EMAIL",
    "PHONE": "PHONE",
    "PERSON_NAME": "NAME",
    "REVISION_AUTHOR": "NAME",
    "GPS_COORDINATES": "LOCATION",
    "ADDRESS": "ADDRESS",
    "COMMENT": "COMMENT",
    "HIDDEN_TEXT": "HIDDEN TEXT",
    "COVERED_TEXT": "HIDDEN TEXT",
    "SOFTWARE_FINGERPRINT": "SOFTWARE",
    "EMBEDDED_OBJECT": "EMBEDDED FILE",
    "EMBEDDED_IMAGE": "IMAGE",
    "JAVASCRIPT": "SCRIPT",
    "FORM_FIELD": "FORM FIELD",
    "AADHAAR": "ID NUMBER",
    "PAN": "ID NUMBER",
    "CARD": "CARD NUMBER",
    "CUSTOM_PROPERTY": "PROPERTY",
    "USER_SPECIFIED": "REDACTED",
}


def category_label(ftype: str) -> str:
    return CATEGORY.get(ftype, "REDACTED")


# Human-readable name + one-line explanation for each finding type, shown in the UI
# so a non-technical user understands what was found and why it matters.
TYPE_INFO = {
    "SOFTWARE_FINGERPRINT": ("Software fingerprint",
        "The app or tool that created the file (e.g. Word version, PDF producer). Reveals your software environment."),
    "REVISION_AUTHOR": ("Author / editor name",
        "The name of whoever created or last edited the file, stored in its metadata."),
    "EMAIL": ("Email address", "An email address found in the file's text."),
    "PHONE": ("Phone number", "A phone number found in the file's text."),
    "PERSON_NAME": ("Person name", "A person's name detected in the text."),
    "ADDRESS": ("Postal address", "A street or postal address."),
    "GPS_COORDINATES": ("GPS location", "The exact coordinates where a photo was taken."),
    "COMMENT": ("Review comment", "A comment left in the document, invisible in normal view."),
    "HIDDEN_TEXT": ("Deleted (tracked) text",
        "Text deleted with tracked changes but still stored inside the file."),
    "COVERED_TEXT": ("Text under a redaction box",
        "Text hidden behind a black rectangle that still copies straight out."),
    "EMBEDDED_OBJECT": ("Embedded / attached file", "A file embedded or attached inside this document."),
    "EMBEDDED_IMAGE": ("Embedded image",
        "A picture inside the document. Kept by default — set it to REMOVE if it is private."),
    "JAVASCRIPT": ("Document JavaScript", "Active script code stored in the PDF."),
    "FORM_FIELD": ("Form field value", "A value filled into an interactive form field."),
    "CARD": ("Payment card number", "A card number (checksum-validated) found in the text."),
    "AADHAAR": ("Aadhaar number", "An Indian Aadhaar ID (checksum-validated)."),
    "PAN": ("PAN number", "An Indian PAN ID found in the text."),
    "CUSTOM_PROPERTY": ("Custom document property", "A custom metadata property saved in the document."),
    "EXIF_THUMBNAIL": ("Embedded thumbnail",
        "A small preview image that can still show the original, uncropped photo."),
    "USER_SPECIFIED": ("Your custom item", "Something you asked us to always remove."),
}


def type_info(ftype: str) -> tuple[str, str]:
    return TYPE_INFO.get(ftype, (ftype.replace("_", " ").title(), ""))


class Tokenizer:
    """Assigns readable, stable pseudonyms to raw values so the UI and the sanitized
    file show "Person 1" / "Email 2" instead of an asterisk-blurred value.

    The raw value never appears — only the token. The same raw value within one
    document always maps to the same token (so one person reads as one "Person N"
    everywhere). ``EXIF_THUMBNAIL`` keeps its descriptive, non-raw preview.
    """

    _FAMILY = {
        "REVISION_AUTHOR": "Person",
        "PERSON_NAME": "Person",
        "EMAIL": "Email",
        "PHONE": "Phone",
        "GPS_COORDINATES": "Location",
        "COMMENT": "Comment",
        "HIDDEN_TEXT": "Hidden text",
        "COVERED_TEXT": "Hidden text",
        "SOFTWARE_FINGERPRINT": "Software",
        "EMBEDDED_OBJECT": "Embedded object",
        "JAVASCRIPT": "Script",
        "FORM_FIELD": "Form field",
        "CUSTOM_PROPERTY": "Property",
        "USER_SPECIFIED": "Your item",
        "ADDRESS": "Address",
        "AADHAAR": "ID number",
        "PAN": "ID number",
        "CARD": "Card",
    }

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._map: dict[tuple, str] = {}

    def token(self, ftype: str, raw: str) -> Optional[str]:
        """Return a stable token for (type-family, raw). None => keep existing preview."""
        family = self._FAMILY.get(ftype)
        if family is None:
            return None
        key = (family, raw)
        if key in self._map:
            return self._map[key]
        self._counts[family] = self._counts.get(family, 0) + 1
        tok = f"{family} {self._counts[family]}"
        self._map[key] = tok
        return tok


class IdGen:
    """Single monotonic id source passed down the whole analyze call.

    Sharing one instance across ``docx.analyze`` and ``text_pii.analyze_text``
    prevents id collisions that would silently corrupt the secrets map and make the
    verifier report nonsense (contract amendment #3).
    """

    def __init__(self, prefix: str = "f") -> None:
        self._n = 0
        self._prefix = prefix

    def next(self) -> str:
        self._n += 1
        return f"{self._prefix}_{self._n:02d}"


@dataclass
class Finding:
    id: str                 # "f_01"
    type: str               # GPS_COORDINATES | PERSON_NAME | EMAIL | PHONE | COMMENT |
                            # REVISION_AUTHOR | SOFTWARE_FINGERPRINT | EMBEDDED_OBJECT |
                            # HIDDEN_TEXT | COVERED_TEXT | EXIF_THUMBNAIL | AADHAAR | PAN | CARD
    location: str           # "docProps/core.xml:creator" — human-readable
    visibility: Visibility
    value_hash: str         # sha256 of the raw value
    value_preview: str      # "J*** S****" — masked, safe to render
    severity: Severity
    decision: Optional[Action] = None    # set by policy engine
    removed: Optional[bool] = None       # set by verifier
    note: str = ""                       # set by judge
    meta: dict = field(default_factory=dict)  # machine-usable payload (e.g. PDF rects)


@dataclass
class CoverageItem:
    """One class of exposure and whether analysis actually inspected it.

    Coverage output is generated from analyzer ``coverage()`` calls, never hardcoded
    (invariant §9.8). ``checked=False`` items are the honest false-negative disclosure.
    """
    category: str
    checked: bool
    detail: str = ""
