import numpy as np
import hashlib


def _derive_keystream(key: str, size: int) -> np.ndarray:
    """Generate a deterministic keystream from key using SHA-256 expansion."""
    key_bytes = key.encode("utf-8")
    stream = bytearray()
    counter = 0
    while len(stream) < size:
        h = hashlib.sha256(key_bytes + counter.to_bytes(4, "big")).digest()
        stream.extend(h)
        counter += 1
    return np.frombuffer(bytes(stream[:size]), dtype=np.uint8)


def xor_encrypt(image: np.ndarray, key: str) -> tuple[np.ndarray, dict]:
    """
    Encrypt image using XOR with a SHA-256-expanded keystream.

    Args:
        image: (H, W, C) uint8 numpy array
        key:   Encryption key string

    Returns:
        (encrypted_image, metadata)
    """
    if not key:
        raise ValueError("XOR key must not be empty")

    flat = image.flatten()
    keystream = _derive_keystream(key, flat.size)
    encrypted_flat = np.bitwise_xor(flat, keystream)
    encrypted = encrypted_flat.reshape(image.shape)

    return encrypted.astype(np.uint8), {
        "algorithm": "xor",
        "key_hash": hashlib.sha256(key.encode()).hexdigest()[:16],
        "shape": list(image.shape),
    }


def xor_decrypt(encrypted: np.ndarray, key: str, metadata: dict) -> np.ndarray:
    """XOR decryption is identical to encryption (symmetric)."""
    decrypted, _ = xor_encrypt(encrypted, key)
    return decrypted
