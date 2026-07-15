import numpy as np
import hashlib


def _key_to_seed(key: str) -> int:
    """Convert key string to a 32-bit integer seed."""
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big")


def perm_encrypt(image: np.ndarray, key: str) -> tuple[np.ndarray, dict]:
    """
    Encrypt image by permuting (shuffling) pixels spatially using a
    seeded Fisher-Yates shuffle. Works on flattened pixel indices.

    Args:
        image: (H, W, C) uint8 numpy array
        key:   Encryption key string

    Returns:
        (encrypted_image, metadata)
    """
    if not key:
        raise ValueError("Pixel permutation key must not be empty")

    h, w, c = image.shape
    n_pixels = h * w

    rng = np.random.default_rng(seed=_key_to_seed(key))
    perm_indices = rng.permutation(n_pixels)  # shape (n_pixels,)

    flat = image.reshape(n_pixels, c)         # (n_pixels, C)
    shuffled = flat[perm_indices]             # apply permutation
    encrypted = shuffled.reshape(image.shape)

    return encrypted.astype(np.uint8), {
        "algorithm": "perm",
        "shape": list(image.shape),
        "key_hash": hashlib.sha256(key.encode()).hexdigest()[:16],
    }


def perm_decrypt(encrypted: np.ndarray, key: str, metadata: dict) -> np.ndarray:
    """Decrypt by applying the inverse permutation."""
    if not key:
        raise ValueError("Pixel permutation key must not be empty")

    shape = metadata.get("shape") or list(encrypted.shape)
    h, w, c = shape
    n_pixels = h * w

    rng = np.random.default_rng(seed=_key_to_seed(key))
    perm_indices = rng.permutation(n_pixels)

    # Compute inverse permutation
    inv_perm = np.empty_like(perm_indices)
    inv_perm[perm_indices] = np.arange(n_pixels)

    flat = encrypted.reshape(n_pixels, c)
    restored = flat[inv_perm]
    return restored.reshape(shape).astype(np.uint8)
