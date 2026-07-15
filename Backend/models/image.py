from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from models.database import Base


class Image(Base):
    __tablename__ = "images"

    id:            Mapped[int]      = mapped_column(Integer, primary_key=True)
    user_id:       Mapped[int]      = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    filename:      Mapped[str]      = mapped_column(String(255), nullable=False)   # UUID on disk
    original_name: Mapped[str|None] = mapped_column(String(255), nullable=True)   # user's original
    url:           Mapped[str]      = mapped_column(String(512), nullable=False)   # public URL
    file_size:     Mapped[int|None] = mapped_column(Integer, nullable=True)
    mime_type:     Mapped[str|None] = mapped_column(String(64), nullable=True)
    uploaded_at:   Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user:    Mapped["User"]          = relationship(back_populates="images")
    results: Mapped[list["Result"]]  = relationship(back_populates="image", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "url":           self.url,
            "filename":      self.filename,
            "original_name": self.original_name,
            "file_size":     self.file_size,
            "mime_type":     self.mime_type,
            "uploaded_at":   self.uploaded_at.isoformat() if self.uploaded_at else None,
            "result_count":  len(self.results),
        }
