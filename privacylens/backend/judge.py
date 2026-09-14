"""Remote LLM auditor — optional, advisory, escalate-only. (Google Gemini.)

Contract (invariant §9.5): the judge may TIGHTEN KEEP -> WARN. It may NEVER loosen a
REMOVE, and it never touches a file. The clamp is enforced in code here, not by
trusting the model's output.

What leaves the machine, only when GEMINI_API_KEY is set: typed labels, hashes,
decisions, intent, and the list of unchecked coverage categories. NEVER the file,
the sanitized file, extracted text, masked/tokenized previews, or any raw value.

Offline path (no key, or any error/timeout) returns {"available": False}. This is
the path built first and the one the demo runs; every local guarantee holds without
the network.
"""
from __future__ import annotations

import json
import os

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

_SYSTEM = (
    "You are a privacy-sanitization AUDITOR. You receive typed findings (labels, "
    "hashes, decisions), the sharing intent, and unchecked coverage categories. You "
    "never see the file or any raw value. Reply ONLY with JSON of the form "
    '{"advice":[{"id":"f_01","recommend":"WARN","note":"..."}],'
    '"coverage_note":"...","linkage_note":"..."}. You may recommend WARN to tighten '
    "a KEEP. You may not recommend loosening a REMOVE. Notes are short."
)


def _payload(findings, intent, unchecked_categories):
    return {
        "intent": intent,
        "unchecked_categories": list(unchecked_categories),
        "findings": [
            {
                "id": f.id,
                "type": f.type,
                "location": f.location,
                "visibility": f.visibility,
                "value_hash": f.value_hash,
                "severity": f.severity,
                "decision": f.decision,
            }
            for f in findings
        ],
    }


def judge(findings, intent, unchecked_categories):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or requests is None:
        return {"available": False}
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{DEFAULT_MODEL}:generateContent"
        body = {
            "systemInstruction": {"parts": [{"text": _SYSTEM}]},
            "contents": [
                {"role": "user",
                 "parts": [{"text": json.dumps(_payload(findings, intent, unchecked_categories))}]}
            ],
            "generationConfig": {"response_mime_type": "application/json", "maxOutputTokens": 1024},
        }
        r = requests.post(
            url,
            headers={"x-goog-api-key": api_key, "content-type": "application/json"},
            json=body,
            timeout=4,
        )
        data = r.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        parsed = json.loads(text)
        return {
            "available": True,
            "advice": parsed.get("advice", []),
            "coverage_note": parsed.get("coverage_note", ""),
            "linkage_note": parsed.get("linkage_note", ""),
        }
    except Exception:
        # Fail toward more privacy: no advice, all local guarantees still hold.
        return {"available": False}


def apply_advice(findings, result):
    """Enforce the clamp. Only KEEP -> WARN is applied. REMOVE is never loosened."""
    if not result.get("available"):
        return findings
    advice = {a.get("id"): a for a in result.get("advice", []) if a.get("id")}
    for f in findings:
        a = advice.get(f.id)
        if not a:
            continue
        note = (a.get("note") or "").strip()
        if note:
            f.note = note
        if a.get("recommend") == "WARN" and f.decision == "KEEP":
            f.decision = "WARN"  # tighten only
        # Any attempt to move REMOVE -> KEEP is silently discarded.
    return findings
