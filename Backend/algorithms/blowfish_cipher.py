import numpy as np
import hashlib
import os
import base64
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad


def _derive_key(key: str) -> bytes:
    return hashlib.sha256(key.encode("utf-8")).digest()[:16]


def blowfish_encrypt(image: np.ndarray, key: str) -> tuple[np.ndarray, dict]:
    if not key:
        raise ValueError("Blowfish key must not be empty")

    bf_key = _derive_key(key)
    iv = os.urandom(8)

    raw_bytes = image.tobytes()
    padded = pad(raw_bytes, Blowfish.block_size)
    cipher = Blowfish.new(bf_key, Blowfish.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(padded)

    enc_visual = np.frombuffer(encrypted_bytes[:image.size], dtype=np.uint8).reshape(image.shape)

    return enc_visual.astype(np.uint8), {
        "algorithm": "blowfish",
        "iv": base64.b64encode(iv).decode("utf-8"),
        "encrypted_payload": base64.b64encode(encrypted_bytes).decode("utf-8"),
        "shape": list(image.shape),
        "original_size": image.size,
    }


def blowfish_decrypt(encrypted: np.ndarray, key: str, metadata: dict) -> np.ndarray:
    if not key:
        raise ValueError("Blowfish key must not be empty")

    bf_key = _derive_key(key)
    iv = base64.b64decode(metadata["iv"])
    shape = metadata["shape"]

    payload_b64 = metadata.get("encrypted_payload")
    if payload_b64:
        encrypted_bytes = base64.b64decode(payload_b64)
    else:
        encrypted_bytes = pad(encrypted.tobytes(), Blowfish.block_size)

    cipher = Blowfish.new(bf_key, Blowfish.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted_bytes = unpad(decrypted_padded, Blowfish.block_size)

    return np.frombuffer(decrypted_bytes, dtype=np.uint8).reshape(shape)
