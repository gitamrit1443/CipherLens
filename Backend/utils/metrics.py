import numpy as np
import time


def compute_metrics(original: np.ndarray, encrypted: np.ndarray) -> dict:
    """
    Compute standard image encryption quality metrics.

    Args:
        original:  Original image as uint8 numpy array (H, W, C)
        encrypted: Encrypted image as uint8 numpy array (H, W, C)

    Returns:
        dict with keys: mse, psnr, ssim, npcr, uaci, entropy
    """
    orig = original.astype(np.float64)
    enc  = encrypted.astype(np.float64)

    mse  = _mse(orig, enc)
    psnr = _psnr(mse)
    ssim = _ssim(orig, enc)
    npcr = _npcr(original, encrypted)
    uaci = _uaci(original, encrypted)
    entropy = _entropy(encrypted)

    return {
        "mse":     round(mse, 4),
        "psnr":    round(psnr, 4),
        "ssim":    round(ssim, 6),
        "npcr":    round(npcr, 4),
        "uaci":    round(uaci, 4),
        "entropy": round(entropy, 4),
    }


def _mse(orig: np.ndarray, enc: np.ndarray) -> float:
    return float(np.mean((orig - enc) ** 2))


def _psnr(mse: float) -> float:
    if mse == 0:
        return float("inf")
    return 20 * np.log10(255.0 / np.sqrt(mse))


def _ssim(orig: np.ndarray, enc: np.ndarray) -> float:
    """Simplified per-channel mean SSIM."""
    C1 = (0.01 * 255) ** 2
    C2 = (0.03 * 255) ** 2

    ssim_vals = []
    for c in range(orig.shape[2]):
        o = orig[:, :, c]
        e = enc[:, :, c]

        mu_o = np.mean(o)
        mu_e = np.mean(e)
        sigma_o = np.var(o)
        sigma_e = np.var(e)
        sigma_oe = np.mean((o - mu_o) * (e - mu_e))

        num = (2 * mu_o * mu_e + C1) * (2 * sigma_oe + C2)
        den = (mu_o**2 + mu_e**2 + C1) * (sigma_o + sigma_e + C2)
        ssim_vals.append(num / den if den != 0 else 0.0)

    return float(np.mean(ssim_vals))


def _npcr(orig: np.ndarray, enc: np.ndarray) -> float:
    """
    Number of Pixel Change Rate (%).
    A good cipher should have NPCR close to 99.6%.
    """
    diff = orig.astype(np.int16) - enc.astype(np.int16)
    changed = np.count_nonzero(diff)
    total = orig.size
    return (changed / total) * 100.0


def _uaci(orig: np.ndarray, enc: np.ndarray) -> float:
    """
    Unified Average Changing Intensity (%).
    Ideal value is ~33.46% for a secure cipher.
    """
    diff = np.abs(orig.astype(np.int16) - enc.astype(np.int16))
    return float(np.mean(diff) / 255.0 * 100.0)


def _entropy(enc: np.ndarray) -> float:
    """
    Shannon entropy of the encrypted image (bits per pixel per channel).
    A perfectly random image has entropy ≈ 8.0.
    """
    entropies = []
    flat = enc.flatten()
    hist, _ = np.histogram(flat, bins=256, range=(0, 255))
    hist = hist[hist > 0]
    prob = hist / hist.sum()
    entropies.append(-np.sum(prob * np.log2(prob)))
    return float(np.mean(entropies))
