import os
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from models.database import get_db
from models.image import Image
from models.result import Result
from models.user import User
from security.dependencies import get_current_user
from security.file_security import validate_and_sanitize_upload, FileSecurityError
from security.rate_limiter import limiter, UPLOAD_LIMIT
from security.audit_log import log_upload
from config import settings

router = APIRouter(prefix="/api/images", tags=["Images"])


@router.post("/upload", status_code=status.HTTP_201_CREATED)
@limiter.limit(UPLOAD_LIMIT)
async def upload_image(
    request: Request,
    file: UploadFile = File(..., alias="image"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    raw = await file.read()
    try:
        meta = validate_and_sanitize_upload(
            raw=raw, original_filename=file.filename or "upload",
            upload_dir=settings.upload_dir, base_url=settings.BASE_URL,
            allowed_extensions=settings.ALLOWED_EXTENSIONS,
            max_bytes=settings.max_upload_bytes,
        )
    except FileSecurityError as e:
        raise HTTPException(status_code=400, detail=str(e))

    image = Image(user_id=user.id, filename=meta["filename"],
                  original_name=meta["original_name"], url=meta["url"],
                  file_size=meta["file_size"], mime_type=meta["mime_type"])
    db.add(image)
    await db.commit()
    await db.refresh(image)
    log_upload(user.id, meta["filename"], request)

    # Build dict manually — avoid lazy load of results
    return {"success": True, "image": {
        "id": image.id, "url": image.url, "filename": image.filename,
        "original_name": image.original_name, "file_size": image.file_size,
        "mime_type": image.mime_type,
        "uploaded_at": image.uploaded_at.isoformat() if image.uploaded_at else None,
        "result_count": 0,
    }}


@router.get("/")
async def list_images(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * per_page
    count_q = await db.execute(select(func.count()).select_from(Image).where(Image.user_id == user.id))
    total = count_q.scalar_one()

    result = await db.execute(
        select(Image).where(Image.user_id == user.id)
        .order_by(Image.uploaded_at.desc()).offset(offset).limit(per_page)
        .options(selectinload(Image.results))
    )
    images = result.scalars().all()

    return {"success": True, "images": [img.to_dict() for img in images],
            "total": total, "page": page,
            "per_page": per_page, "pages": (total + per_page - 1) // per_page}


@router.get("/{image_id}")
async def get_image(image_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Image).where(Image.id == image_id, Image.user_id == user.id)
        .options(selectinload(Image.results))
    )
    image = result.scalar_one_or_none()
    if not image:
        raise HTTPException(status_code=404, detail="Image not found")
    return {"success": True, "image": image.to_dict()}


@router.delete("/{image_id}")
async def delete_image(image_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Image).where(Image.id == image_id, Image.user_id == user.id)
        .options(selectinload(Image.results))
    )
    image = result.scalar_one_or_none()
    if not image:
        raise HTTPException(status_code=404, detail="Image not found")

    upload_dir = settings.upload_dir
    for r in image.results:
        if r.encrypted_filename:
            p = os.path.join(upload_dir, r.encrypted_filename)
            if os.path.exists(p): os.remove(p)

    p = os.path.join(upload_dir, image.filename)
    if os.path.exists(p): os.remove(p)

    await db.delete(image)
    await db.commit()
    return {"success": True, "message": "Image and all associated results deleted"}
