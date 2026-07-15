"""
Layer 5 — File Upload Security (FastAPI version, no Flask deps).
Same 9-step pipeline: magic bytes → size cap → Pillow decode → re-encode → UUID → jail check.
"""
import os, uuid, io
import numpy as np
from PIL import Image as PILImage

MAGIC_SIGNATURES = {
    "png":  [(0, b"\x89PNG\r\n\x1a\n")],
    "jpg":  [(0, b"\xff\xd8\xff")],
    "jpeg": [(0, b"\xff\xd8\xff")],
    "webp": [(0, b"RIFF"), (8, b"WEBP")],
    "bmp":  [(0, b"BM")],
}


class FileSecurityError(ValueError):
    pass


def _detect_magic(data: bytes) -> str | None:
    for fmt, checks in MAGIC_SIGNATURES.items():
        if all(data[offset: offset + len(sig)] == sig for offset, sig in checks):
            return fmt
    return None


def validate_and_sanitize_upload(
    raw: bytes,
    original_filename: str,
    upload_dir: str,
    base_url: str,
    allowed_extensions: set[str] | None = None,
    max_bytes: int = 16 * 1024 * 1024,
) -> dict:
    """
    Full 9-step security pipeline for an uploaded image.
    raw: already-read bytes from the upload.
    Returns metadata dict on success, raises FileSecurityError on violation.
    """
    allowed = allowed_extensions or {"png", "jpg", "jpeg", "webp", "bmp"}

    # 1. Original filename — stored for reference, NEVER used on disk
    original_filename = (original_filename or "upload").strip()
    if not original_filename or original_filename == ".":
        raise FileSecurityError("Invalid filename")

    # 2. Extension check (fast first gate)
    if "." not in original_filename:
        raise FileSecurityError("File must have an extension")
    declared_ext = original_filename.rsplit(".", 1)[1].lower()
    if declared_ext not in allowed:
        raise FileSecurityError(f"Extension '.{declared_ext}' not allowed. Accepted: {', '.join(sorted(allowed))}")

    # 3. Size cap
    if len(raw) > max_bytes:
        raise FileSecurityError(f"File too large. Maximum is {max_bytes // (1024*1024)} MB")
    if len(raw) == 0:
        raise FileSecurityError("Empty file")

    # 4. Magic bytes (defeats extension spoofing)
    detected = _detect_magic(raw)
    if detected is None:
        raise FileSecurityError("File content does not match any recognised image format")
    if declared_ext in ("jpg", "jpeg"):
        if detected not in ("jpg", "jpeg"):
            raise FileSecurityError("Extension/content mismatch — possible spoofed file")
    elif declared_ext != detected:
        raise FileSecurityError(f"Extension '.{declared_ext}' does not match detected format '{detected}'")

    # 5. Pillow decode (catches corrupt / polyglot files)
    try:
        pil_img = PILImage.open(io.BytesIO(raw)).convert("RGB")
        pil_img.verify()
    except Exception as e:
        raise FileSecurityError(f"Image decode failed: {e}")

    # Re-open after verify()
    pil_img = PILImage.open(io.BytesIO(raw)).convert("RGB")

    # 6. Dimension sanity (decompression bomb check)
    if pil_img.width > 8000 or pil_img.height > 8000:
        raise FileSecurityError("Image dimensions too large (max 8000×8000 px)")

    # 7. Re-encode as clean PNG (strips EXIF, XMP, embedded code)
    clean_buf = io.BytesIO()
    pil_img.save(clean_buf, format="PNG", optimize=False)
    clean_bytes = clean_buf.getvalue()

    # 8. UUID filename — attacker's filename never touches filesystem
    safe_filename = f"{uuid.uuid4().hex}.png"

    # 9. Path jail check
    os.makedirs(upload_dir, exist_ok=True)
    abs_dir  = os.path.realpath(upload_dir)
    dest     = os.path.realpath(os.path.join(abs_dir, safe_filename))
    if not dest.startswith(abs_dir + os.sep):
        raise FileSecurityError("Path traversal detected")

    with open(dest, "wb") as f:
        f.write(clean_bytes)

    return {
        "filename":      safe_filename,
        "original_name": original_filename,
        "url":           f"{base_url}/uploads/{safe_filename}",
        "file_size":     len(clean_bytes),
        "mime_type":     "image/png",
    }
