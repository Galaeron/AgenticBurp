"""Small benign generated files for a file input (driver_capture.file_uploads).

`benign_file(accept, nonce)` returns one file whose type the input's `accept`
attribute allows, as (filename, mime type, bytes), or None when no type it can
generate matches. Every file is tiny, valid for its type and inert: plain text,
a 1x1 image, a one-page PDF, a zip holding one text file. Nothing executable or
scriptable (no HTML, SVG or office macro formats). The nonce goes in the name and,
for the text types, the content, so the upload request is recognisable.
"""
from __future__ import annotations

import io
import struct
import zipfile
import zlib


def _png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
    header = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)          # 1x1, 8-bit grey
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(b"\x00\xff")) + chunk(b"IEND", b""))


# The standard 1x1 transparent GIF.
_GIF = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000"
                     "010001000002024401003b")


def _pdf(nonce: str) -> bytes:
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>",
               b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] >>"]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n% harness upload " + nonce.encode() + b"\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % number + body + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for offset in offsets:
        out.write(b"%010d 00000 n \n" % offset)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
              % (len(objects) + 1, xref))
    return out.getvalue()


def _zip(nonce: str) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("harness-upload.txt", f"harness upload test {nonce}\n")
    return out.getvalue()


# (extension, extra extensions, mime types, builder), in order of preference:
# text first, then the smallest images, then documents and archives.
_TYPES = (
    ("txt", ("text",), ("text/plain",), lambda n: f"harness upload test {n}\n".encode()),
    ("png", (), ("image/png",), lambda n: _png()),
    ("gif", (), ("image/gif",), lambda n: _GIF),
    ("pdf", (), ("application/pdf",), _pdf),
    ("json", (), ("application/json", "text/json"),
     lambda n: ('{"harness_upload_test": "%s"}\n' % n).encode()),
    ("csv", (), ("text/csv",), lambda n: f"harness,upload\ntest,{n}\n".encode()),
    ("xml", (), ("application/xml", "text/xml"),
     lambda n: f"<?xml version=\"1.0\"?><harness-upload-test>{n}</harness-upload-test>\n".encode()),
    ("zip", (), ("application/zip", "application/x-zip-compressed"), _zip),
)


def _allows(accept: list[str], ext: str, extras: tuple, mimes: tuple) -> bool:
    if not accept:
        return True
    for token in accept:
        if token.startswith("."):
            if token[1:] in (ext, *extras):
                return True
        elif token in ("*/*", "*"):
            return True
        elif token.endswith("/*"):
            if any(m.startswith(token[:-1]) for m in mimes):
                return True
        elif token in mimes:
            return True
    return False


def benign_file(accept: str, nonce: str) -> tuple[str, str, bytes] | None:
    """(filename, mime type, content) of a benign file `accept` allows, or None."""
    tokens = [t.strip().lower().split(";", 1)[0].strip()
              for t in (accept or "").split(",")]
    tokens = [t for t in tokens if t]
    for ext, extras, mimes, build in _TYPES:
        if _allows(tokens, ext, extras, mimes):
            return f"harness-upload-{nonce}.{ext}", mimes[0], build(nonce)
    return None
