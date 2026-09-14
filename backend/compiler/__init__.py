"""Compiler registry. Extension -> module exposing compile(path, findings, secrets)."""
from . import docx, image, pdf

COMPILERS = {
    ".docx": docx,
    ".pdf": pdf,
    ".jpg": image,
    ".jpeg": image,
    ".png": image,
}
