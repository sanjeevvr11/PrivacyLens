# PrivacyLens

> **Other tools ask you to trust them; we prove what left the file.**

PrivacyLens detects what a shared file carries beyond its visible contents — author metadata, internal comments, tracked revisions, cropped photo EXIF thumbnails, GPS geotags, and text hidden beneath visual redaction overlays. It sanitizes the file according to your specific sharing **intent**, and then **proves** removal with an independent, format-ignorant, byte-level verifier that shares zero assumptions or code with the detector.

---

## 🎯 The Core Architectural Rule

**Detection and verification must use independent mechanisms.**

Traditional metadata strippers re-scan the sanitized file with the same parser that detected the issues. That is circular: if a parser has a blind spot, it misses the leak in both passes, giving a false sense of security.

| Stage | Mechanism | Question It Answers |
|---|---|---|
| **Detection** | **Structural** — parse OOXML parts, PDF objects, EXIF tags, NER & checksums | *"What is inside this file?"* |
| **Verification** | **Format-Ignorant** — decompress streams, raw byte search for `value` & `sha256(value)` | *"Did it actually leave the file?"* |
| **Remote Judge (Optional)** | **Advisory LLM** — receives typed labels & hashes only, never raw data | *"Was that the right decision for this intent?"* |

---

## 🔄 The 5-Stage Pipeline

```text
Original File (Local, never leaves your machine)
  │
  ├─► 1. ANALYZE     Format-aware parsers + regex + checksums + spaCy NER
  │
  ├─► 2. DECIDE      Policy engine matrix (KEEP / WARN / REMOVE) by Intent
  │
  ├─► 3. COMPILE     Lossless transformation passes into a brand-new container
  │
  ├─► 4. VERIFY      Independent byte-level & decompressed stream search
  │
  └─► 5. [OPTIONAL]  Advisory LLM auditor (Google Gemini) for coverage & linkage risk
      │
      ▼
Final Report + Verified Safe Download
```

---

## 🛡️ Supported Exposure Vectors

- **DOCX / Word Documents:**
  - Revision author & editor identity (`docProps/core.xml`)
  - Application & company fingerprints (`docProps/app.xml`)
  - Hidden review comments & author signatures (`word/comments.xml`)
  - Tracked changes / deletions (`w:del`, `w:ins`)
  - Embedded objects & attachments (`word/embeddings/*`)
  - Body & header/footer PII: Names, Postal Addresses, Emails, Phone numbers
- **PDF Documents:**
  - DocInfo author, creator, and producer metadata
  - XMP metadata packets
  - Fake redactions (text underlying opaque black boxes / rectangles)
  - Annotations & popup comments
  - Embedded / attached files & document-level JavaScript
  - Interactive AcroForm field values
- **Images (JPEG):**
  - EXIF tags & camera serial identifiers
  - GPS latitude & longitude coordinates
  - **Embedded EXIF thumbnails** (often reveal the original uncropped photo!)
- **Checksum-Validated & Structured PII:**
  - Person Names (spaCy NER + honorifics + field prefixes)
  - Postal & Street Addresses (US, Indian PIN, UK formats)
  - Emails & Phone Numbers
  - Indian Aadhaar (Verhoeff checksum-validated)
  - Indian PAN Numbers
  - Credit / Debit Cards (Luhn checksum-validated)

---

## 🚀 Quick Start

### 1. Clone & Setup Environment

```bash
git clone https://github.com/sanjeevvr11/PrivacyLens.git
cd PrivacyLens

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2. Configure Environment (Optional)

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

If you wish to enable the advisory LLM auditor, set your Google Gemini API key:
```env
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.0-flash
```
*(Note: Without a key, PrivacyLens runs 100% offline with zero cloud dependency. All core guarantees and verification hold locally.)*

### 3. Run Locally

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser at **`http://127.0.0.1:8000`**.

---

## 🧪 Interactive Demo Files

Pre-generated demo files highlighting real-world failure modes are available in [`demo/`](demo/):

1. **`demo/photo_cropped.jpg`**: A cropped photo whose embedded EXIF thumbnail still shows the original uncropped scene and GPS coordinates.
2. **`demo/report_fake_redaction.pdf`**: A document with an opaque black box drawn over an undercover agent's name; PrivacyLens detects and removes the text glyphs underneath.
3. **`demo/resume_geotagged.docx`**: A resume containing author metadata, tracked deletions, private comments, contact details, and address.

To regenerate fresh demo files at any time:
```bash
python demo/make_demos.py
```

---

## 📡 API Reference

| Endpoint | Method | Input | Output |
|---|---|---|---|
| `/analyze` | `POST` | `multipart/form-data` file | `{ session_id, findings[] }` |
| `/sanitize` | `POST` | JSON `{ session_id, intent, overrides? }` | `{ findings[], coverage[], download_url, judge }` |
| `/download/{session_id}` | `GET` | — | Fresh sanitized file container |

### Supported Intents

- **`job_application`**: Preserves legitimate contact info (name, email) while stripping hidden revision history, comments, and internal metadata.
- **`public_sharing`**: Aggressive sanitization (removes or warns on all PII, GPS, metadata, and author traces).
- **`internal_sharing`**: Preserves collaboration artifacts while flagging sensitive external identifiers.
- **`legal_hold`**: Forbids removal of revision history and comments to prevent spoliation of evidence.

---

## 🔒 Privacy & Security Invariants

1. **Raw PII Never Leaves:** The server never stores raw values in response payloads or logs. Raw values live only in a transient in-memory secrets map for the local compilation and verification step.
2. **Advisory Judge Isolation:** If the Gemini advisory judge is invoked, it receives only typed labels (e.g. `EMAIL`, `GPS_COORDINATES`), hashes, and coverage categories. It **never** receives the document, extracted text, or raw PII values.
3. **Never Edit In-Place:** Sanitization always reconstructs a fresh file container to prevent residual bytes from surviving in archive gaps or object revision tables.

---

## 📄 License

MIT License. Designed and developed by **Perpetually Curious**.
