import base64
import io
import numpy as np
from PIL import Image


def decode_image(image_b64: str) -> np.ndarray:
    """Decode a base64 image string to a numpy array (H, W, C) uint8."""
    if "," in image_b64:
        image_b64 = image_b64.split(",", 1)[1]

    try:
        raw = base64.b64decode(image_b64)
    except Exception:
        raise ValueError("Invalid base64 encoding for image")

    try:
        img = Image.open(io.BytesIO(raw)).convert("RGB")
    except Exception:
        raise ValueError("Cannot decode image — ensure it is a valid PNG or JPEG")

    return np.array(img, dtype=np.uint8)


def encode_image(arr: np.ndarray) -> str:
    """Encode a numpy array back to a base64 PNG string (data URI)."""
    arr = np.clip(arr, 0, 255).astype(np.uint8)
    img = Image.fromarray(arr, mode="RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64}"
