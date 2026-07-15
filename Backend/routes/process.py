import os, time, uuid
import numpy as np
from PIL import Image as PILImage
import io

from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from models.database import get_db
from models.image import Image
from models.result import Result
from models.user import User
from security.dependencies import get_current_user
from security.validators import ProcessRequest, BenchmarkRequest
from security.rate_limiter import limiter, PROCESS_LIMIT
from security.audit_log import log_process
from utils.metrics import compute_metrics
from config import settings

from algorithms.xor_cipher        import xor_encrypt
from algorithms.aes_cipher        import aes_encrypt
from algorithms.des3_cipher       import des3_encrypt
from algorithms.pixel_permutation import perm_encrypt
from algorithms.rc4_cipher        import rc4_encrypt
from algorithms.blowfish_cipher   import blowfish_encrypt

router = APIRouter(prefix="/api/process", tags=["Process"])

ALGORITHM_MAP = {
    "xor": xor_encrypt, "aes": aes_encrypt, "3des": des3_encrypt,
    "perm": perm_encrypt, "rc4": rc4_encrypt, "blowfish": blowfish_encrypt,
}


def _load_image(url: str) -> np.ndarray:
    base_url   = settings.BASE_URL
    upload_dir = settings.upload_dir
    if url.startswith(base_url + "/uploads/"):
        filename  = os.path.basename(url.split("/uploads/")[-1])
        file_path = os.path.realpath(os.path.join(upload_dir, filename))
        jail      = os.path.realpath(upload_dir)
        if not file_path.startswith(jail + os.sep):
            raise PermissionError("Path traversal blocked")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {filename}")
        img = PILImage.open(file_path).convert("RGB")
    else:
        import requests as req
        resp = req.get(url, timeout=10)
        resp.raise_for_status()
        img = PILImage.open(io.BytesIO(resp.content)).convert("RGB")
    return np.array(img, dtype=np.uint8)


def _save_enc(arr: np.ndarray) -> tuple[str, str]:
    fname = f"enc_{uuid.uuid4().hex}.png"
    path  = os.path.join(settings.upload_dir, fname)
    PILImage.fromarray(np.clip(arr, 0, 255).astype(np.uint8)).save(path, format="PNG")
    return fname, f"{settings.BASE_URL}/uploads/{fname}"


@router.post("", status_code=status.HTTP_201_CREATED)
@limiter.limit(PROCESS_LIMIT)
async def process_image(
    body: ProcessRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(select(Image).where(Image.id == body.image_id, Image.user_id == user.id))
    image = res.scalar_one_or_none()
    if not image:
        raise HTTPException(status_code=404, detail="Image not found")

    try:
        orig = _load_image(image.url)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load image: {e}")

    try:
        t0 = time.perf_counter()
        enc_arr, algo_meta = ALGORITHM_MAP[body.algorithm](orig, body.key)
        elapsed_ms = (time.perf_counter() - t0) * 1000
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption failed: {e}")

    metrics = compute_metrics(orig, enc_arr)
    enc_fname, enc_url = _save_enc(enc_arr)

    r = Result(user_id=user.id, image_id=image.id, algorithm=body.algorithm,
               key_hint=body.key[:4]+"****", encrypted_image_url=enc_url,
               encrypted_filename=enc_fname, processing_time_ms=round(elapsed_ms, 2))
    r.metrics = metrics
    r.metadata_dict = algo_meta
    db.add(r)
    await db.commit()
    await db.refresh(r)
    log_process(user.id, body.algorithm, request)

    return {"success": True, "result": r.to_dict(),
            "original_image_url": image.url, "encrypted_image_url": enc_url,
            "metrics": metrics, "processing_time_ms": round(elapsed_ms, 2)}


@router.post("/benchmark", status_code=status.HTTP_201_CREATED)
@limiter.limit(PROCESS_LIMIT)
async def benchmark_image(
    body: BenchmarkRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(select(Image).where(Image.id == body.image_id, Image.user_id == user.id))
    image = res.scalar_one_or_none()
    if not image:
        raise HTTPException(status_code=404, detail="Image not found")

    try:
        orig = _load_image(image.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load image: {e}")

    algos = body.algorithms or list(ALGORITHM_MAP.keys())
    bench_results, saved = [], []

    for algo in algos:
        try:
            t0 = time.perf_counter()
            enc_arr, algo_meta = ALGORITHM_MAP[algo](orig, body.key)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            metrics = compute_metrics(orig, enc_arr)
            enc_fname, enc_url = _save_enc(enc_arr)
            r = Result(user_id=user.id, image_id=image.id, algorithm=algo,
                       key_hint=body.key[:4]+"****", encrypted_image_url=enc_url,
                       encrypted_filename=enc_fname, processing_time_ms=round(elapsed_ms, 2))
            r.metrics = metrics; r.metadata_dict = algo_meta
            saved.append(r)
            bench_results.append({"algorithm": algo, "success": True, "metrics": metrics,
                                   "encrypted_image_url": enc_url, "processing_time_ms": round(elapsed_ms, 2)})
        except Exception as e:
            bench_results.append({"algorithm": algo, "success": False, "error": str(e)})

    if saved:
        db.add_all(saved)
        await db.commit()

    return {"success": True, "image_id": body.image_id, "original_url": image.url,
            "results": bench_results, "total_algorithms": len(algos)}


@router.get("/results")
async def list_results(
    image_id: int | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    base_q = select(Result).where(Result.user_id == user.id)
    if image_id:
        base_q = base_q.where(Result.image_id == image_id)

    count_q = await db.execute(select(func.count()).select_from(Result).where(
        Result.user_id == user.id, *([] if not image_id else [Result.image_id == image_id])
    ))
    total = count_q.scalar_one()

    paged = await db.execute(
        base_q.order_by(Result.created_at.desc())
        .offset((page - 1) * per_page).limit(per_page)
    )
    results = paged.scalars().all()
    return {"success": True, "results": [r.to_dict() for r in results],
            "total": total, "page": page, "per_page": per_page,
            "pages": (total + per_page - 1) // per_page}


@router.get("/results/{result_id}")
async def get_result(result_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    res_q = await db.execute(
        select(Result).where(Result.id == result_id, Result.user_id == user.id)
        .options(selectinload(Result.image))
    )
    r = res_q.scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    d = r.to_dict()
    d["original_image_url"] = r.image.url if r.image else None
    return {"success": True, "result": d}


@router.delete("/results/{result_id}")
async def delete_result(result_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    res_q = await db.execute(select(Result).where(Result.id == result_id, Result.user_id == user.id))
    r = res_q.scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    if r.encrypted_filename:
        p = os.path.join(settings.upload_dir, r.encrypted_filename)
        if os.path.exists(p): os.remove(p)
    await db.delete(r)
    await db.commit()
    return {"success": True, "message": "Result deleted"}
