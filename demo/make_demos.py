"""Generate the three curated demo files.

  demo/photo_cropped.jpg        — cropped photo whose EXIF thumbnail still shows the
                                  original (uncropped) framing, GPS + camera tags intact
  demo/report_fake_redaction.pdf — real text with an opaque black box over a secret;
                                  the covered string still extracts
  demo/resume_geotagged.docx     — creator name, a comment, tracked changes, body email

Run: .venv/bin/python demo/make_demos.py
"""
import io
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- JPG
def make_photo():
    from PIL import Image, ImageDraw
    import piexif

    # Original "uncropped" scene: a wide landscape with a clear landmark on the left.
    orig = Image.new("RGB", (640, 400), (40, 90, 160))
    d = ImageDraw.Draw(orig)
    d.rectangle([20, 250, 160, 380], fill=(200, 60, 60))     # the landmark, left side
    d.ellipse([480, 40, 600, 160], fill=(250, 220, 80))       # sun, right side
    d.text((30, 20), "ORIGINAL FRAMING (landmark visible)", fill=(255, 255, 255))

    # The user crops to the right half — the landmark is gone from the visible pixels.
    cropped = orig.crop((320, 0, 640, 400))

    # But the EXIF thumbnail is generated from the ORIGINAL and embedded intact.
    thumb = orig.copy()
    thumb.thumbnail((160, 100))
    tbuf = io.BytesIO()
    thumb.save(tbuf, format="JPEG")

    gps_ifd = {
        piexif.GPSIFD.GPSLatitudeRef: b"N",
        piexif.GPSIFD.GPSLatitude: [(37, 1), (46, 1), (2999, 100)],   # 37.7758 N
        piexif.GPSIFD.GPSLongitudeRef: b"W",
        piexif.GPSIFD.GPSLongitude: [(122, 1), (25, 1), (1000, 100)], # 122.4194 W
    }
    zeroth = {
        piexif.ImageIFD.Make: b"Canon",
        piexif.ImageIFD.Model: b"Canon EOS 5D",
        piexif.ImageIFD.Software: b"PrivacyLens Demo Camera 1.0",
    }
    exif_bytes = piexif.dump({"0th": zeroth, "Exif": {}, "GPS": gps_ifd,
                              "1st": {}, "thumbnail": tbuf.getvalue()})

    out = os.path.join(HERE, "photo_cropped.jpg")
    cropped.save(out, format="JPEG", exif=exif_bytes, quality=92)
    print("wrote", out)


# --------------------------------------------------------------------------- PDF
def make_pdf():
    import fitz

    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 100), "CONFIDENTIAL INVESTIGATION REPORT", fontsize=16)
    page.insert_text((72, 140), "Subject informant name:", fontsize=12)
    secret = "AGENT MARGARET HALLORAN"
    # Place the secret, then paint an opaque black box over it (fake redaction).
    page.insert_text((260, 140), secret, fontsize=12)
    # The rectangle must cover the text glyphs; approximate their span.
    rect = fitz.Rect(255, 128, 470, 145)
    page.draw_rect(rect, color=(0, 0, 0), fill=(0, 0, 0), fill_opacity=1)
    page.insert_text((72, 180), "This box hides the name on screen — but the text is still there.", fontsize=10)
    doc.set_metadata({"author": "Detective R. Cole", "producer": "PrivacyLens Demo PDF"})

    out = os.path.join(HERE, "report_fake_redaction.pdf")
    doc.save(out)
    doc.close()

    # Confirm the covered string still extracts.
    check = fitz.open(out)
    text = check[0].get_text()
    check.close()
    assert secret in text, "covered text did not extract — demo would not land"
    print("wrote", out, "(covered text still extracts: OK)")


# -------------------------------------------------------------------------- DOCX
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def make_docx():
    ct = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>'''

    root_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>'''

    doc_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdCmt" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>
</Relationships>'''

    core = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
<dc:creator>corp\jsmith</dc:creator>
<cp:lastModifiedBy>corp\jsmith</cp:lastModifiedBy>
</cp:coreProperties>'''

    app = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
<Application>Microsoft Office Word</Application>
<Company>Acme Internal Corp</Company>
</Properties>'''

    document = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="{W}">
<w:body>
<w:p><w:r><w:t>Jane Applicant — Senior Engineer</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">Address: 742 Evergreen Terrace, Springfield, OR 97477</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">Contact: jane.applicant@example.com</w:t></w:r></w:p>
<w:p>
  <w:commentRangeStart w:id="0"/>
  <w:r><w:t xml:space="preserve">I led the migration project </w:t></w:r>
  <w:commentRangeEnd w:id="0"/>
  <w:r><w:commentReference w:id="0"/></w:r>
  <w:ins w:id="1" w:author="Jane Applicant"><w:r><w:t xml:space="preserve">to completion ahead of schedule</w:t></w:r></w:ins>
  <w:del w:id="2" w:author="Jane Applicant"><w:r><w:delText xml:space="preserve"> (was late by two weeks)</w:delText></w:r></w:del>
  <w:r><w:t>.</w:t></w:r>
</w:p>
</w:body>
</w:document>'''

    comments = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:comments xmlns:w="{W}">
<w:comment w:id="0" w:author="Recruiter Bob" w:date="2024-01-01T00:00:00Z">
<w:p><w:r><w:t>Verify this claim before the interview.</w:t></w:r></w:p>
</w:comment>
</w:comments>'''

    parts = {
        "[Content_Types].xml": ct,
        "_rels/.rels": root_rels,
        "word/_rels/document.xml.rels": doc_rels,
        "word/document.xml": document,
        "word/comments.xml": comments,
        "docProps/core.xml": core,
        "docProps/app.xml": app,
    }
    out = os.path.join(HERE, "resume_geotagged.docx")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    print("wrote", out)


if __name__ == "__main__":
    make_photo()
    make_pdf()
    make_docx()
    print("all demo files generated")
