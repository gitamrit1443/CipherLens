import numpy as np
import hashlib
import os
import base64
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def _derive_key(key: str) -> bytes:
    raw = hashlib.sha256(key.encode("utf-8")).digest()
    extended = raw + hashlib.md5(key.encode("utf-8")).digest()
    return extended[:24]


def des3_encrypt(image: np.ndarray, key: str) -> tuple[np.ndarray, dict]:
    if not key:
        raise ValueError("3DES key must not be empty")

    des_key = DES3.adjust_key_parity(_derive_key(key))
    iv = os.urandom(8)

    raw_bytes = image.tobytes()
    padded = pad(raw_bytes, DES3.block_size)
    cipher = DES3.new(des_key, DES3.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(padded)

    enc_visual = np.frombuffer(encrypted_bytes[:image.size], dtype=np.uint8).reshape(image.shape)

    return enc_visual.astype(np.uint8), {
        "algorithm": "3des",
        "iv": base64.b64encode(iv).decode("utf-8"),
        "encrypted_payload": base64.b64encode(encrypted_bytes).decode("utf-8"),
        "shape": list(image.shape),
        "original_size": image.size,
    }


def des3_decrypt(encrypted: np.ndarray, key: str, metadata: dict) -> np.ndarray:
    if not key:
        raise ValueError("3DES key must not be empty")

    des_key = DES3.adjust_key_parity(_derive_key(key))
    iv = base64.b64decode(metadata["iv"])
    shape = metadata["shape"]

    payload_b64 = metadata.get("encrypted_payload")
    if payload_b64:
        encrypted_bytes = base64.b64decode(payload_b64)
    else:
        encrypted_bytes = pad(encrypted.tobytes(), DES3.block_size)

    cipher = DES3.new(des_key, DES3.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted_bytes = unpad(decrypted_padded, DES3.block_size)

    return np.frombuffer(decrypted_bytes, dtype=np.uint8).reshape(shape)
