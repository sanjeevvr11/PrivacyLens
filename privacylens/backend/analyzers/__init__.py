"""Analyzer registry. Extension -> module exposing analyze(path, ids) and coverage()."""
from . import docx, image, pdf

ANALYZERS = {
    ".docx": docx,
    ".pdf": pdf,
    ".jpg": image,
    ".jpeg": image,
    ".png": image,
}
