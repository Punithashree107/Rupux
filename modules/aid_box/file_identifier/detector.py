"""
Core logic for the File Type Identifier tool.

Identifies a file's REAL type by reading its binary signature (magic
bytes) rather than trusting its extension. This is a genuinely useful
security check: malware is often disguised with a harmless extension
(e.g. invoice.pdf.exe, resume.docx that is actually an executable).

No external dependencies (no libmagic needed) -- a small curated
signature table covers the most common formats. Easy to extend.
"""
import os
from dataclasses import dataclass
from typing import Optional

# (signature bytes, offset, description, typical extensions)
SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image", [".png"]),
    (b"\xff\xd8\xff", 0, "JPEG image", [".jpg", ".jpeg"]),
    (b"GIF87a", 0, "GIF image", [".gif"]),
    (b"GIF89a", 0, "GIF image", [".gif"]),
    (b"%PDF-", 0, "PDF document", [".pdf"]),
    (b"PK\x03\x04", 0, "ZIP archive (also docx/xlsx/pptx/jar/apk)", [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]),
    (b"Rar!\x1a\x07\x00", 0, "RAR archive", [".rar"]),
    (b"Rar!\x1a\x07\x01\x00", 0, "RAR5 archive", [".rar"]),
    (b"\x1f\x8b\x08", 0, "GZIP archive", [".gz"]),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive", [".7z"]),
    (b"MZ", 0, "Windows executable / DLL (PE format)", [".exe", ".dll"]),
    (b"\x7fELF", 0, "Linux ELF executable/binary", [".elf", ".so", ".bin"]),
    (b"\xca\xfe\xba\xbe", 0, "Java class file / Mach-O fat binary", [".class"]),
    (b"\xfe\xed\xfa\xce", 0, "Mach-O executable (32-bit)", [""]),
    (b"\xfe\xed\xfa\xcf", 0, "Mach-O executable (64-bit)", [""]),
    (b"ID3", 0, "MP3 audio (with ID3 tag)", [".mp3"]),
    (b"\xff\xfb", 0, "MP3 audio", [".mp3"]),
    (b"RIFF", 0, "RIFF container (WAV/AVI)", [".wav", ".avi"]),
    (b"\x00\x00\x00\x18ftyp", 4, "MP4 video", [".mp4"]),
    (b"OggS", 0, "OGG media", [".ogg"]),
    (b"BM", 0, "BMP image", [".bmp"]),
    (b"{\\rtf1", 0, "Rich Text Format document", [".rtf"]),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "Legacy MS Office document (doc/xls/ppt)", [".doc", ".xls", ".ppt"]),
    (b"#!/", 0, "Shell/interpreter script", [".sh", ".py", ".pl"]),
    (b"<?xml", 0, "XML document", [".xml"]),
    (b"<!DOCTYPE html", 0, "HTML document", [".html", ".htm"]),
    (b"<html", 0, "HTML document", [".html", ".htm"]),
    (b"SQLite format 3\x00", 0, "SQLite database", [".db", ".sqlite"]),
]

MAX_READ = 64  # bytes needed to check every signature above


@dataclass
class IdentificationResult:
    filename: str
    extension: str
    detected_type: Optional[str]
    matched_extensions: list
    extension_mismatch: bool
    file_size: int
    error: Optional[str] = None


def identify_file(path: str) -> IdentificationResult:
    filename = os.path.basename(path)
    ext = os.path.splitext(filename)[1].lower()

    try:
        with open(path, "rb") as f:
            header = f.read(MAX_READ)
        size = os.path.getsize(path)
    except Exception as e:
        return IdentificationResult(
            filename=filename, extension=ext, detected_type=None,
            matched_extensions=[], extension_mismatch=False,
            file_size=0, error=str(e),
        )

    for sig, offset, description, exts in SIGNATURES:
        end = offset + len(sig)
        if header[offset:end] == sig:
            mismatch = bool(exts) and ext not in exts and exts != [""]
            return IdentificationResult(
                filename=filename, extension=ext, detected_type=description,
                matched_extensions=exts, extension_mismatch=mismatch,
                file_size=size,
            )

    # No signature matched -- likely plain text or unknown binary
    is_text = _looks_like_text(header)
    detected = "Plain text / unknown format" if is_text else "Unknown binary format"
    return IdentificationResult(
        filename=filename, extension=ext, detected_type=detected,
        matched_extensions=[], extension_mismatch=False, file_size=size,
    )


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return True
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data) > 0.85
