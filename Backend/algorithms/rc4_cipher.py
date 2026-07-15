import numpy as np
import hashlib


def _ksa(key_bytes: bytes) -> list[int]:
    """RC4 Key Scheduling Algorithm."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def _prga(S: list[int], length: int) -> np.ndarray:
    """RC4 Pseudo-Random Generation Algorithm — produce keystream of `length` bytes."""
    S = S[:]
    i = j = 0
    keystream = np.empty(length, dtype=np.uint8)
    for k in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream[k] = S[(S[i] + S[j]) % 256]
    return keystream


def _derive_key(key: str) -> bytes:
    """Derive a 16-byte key for RC4."""
    return hashlib.sha256(key.encode("utf-8")).digest()[:16]


def rc4_encrypt(image: np.ndarray, key: str) -> tuple[np.ndarray, dict]:
    """
    Encrypt image using the RC4 stream cipher.

    Args:
        image: (H, W, C) uint8 numpy array
        key:   Encryption key string

    Returns:
        (encrypted_image, metadata)
    """
    if not key:
        raise ValueError("RC4 key must not be empty")

    key_bytes = _derive_key(key)
    S = _ksa(key_bytes)

    flat = image.flatten()
    keystream = _prga(S, flat.size)
    encrypted_flat = np.bitwise_xor(flat, keystream)
    encrypted = encrypted_flat.reshape(image.shape)

    return encrypted.astype(np.uint8), {
        "algorithm": "rc4",
        "key_hash": hashlib.sha256(key.encode()).hexdigest()[:16],
        "shape": list(image.shape),
    }


def rc4_decrypt(encrypted: np.ndarray, key: str, metadata: dict) -> np.ndarray:
    """RC4 decryption is identical to encryption (symmetric stream cipher)."""
    decrypted, _ = rc4_encrypt(encrypted, key)
    return decrypted
