import json
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from models.database import Base


class Result(Base):
    __tablename__ = "results"

    id:       Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id:  Mapped[int] = mapped_column(Integer, ForeignKey("users.id"),  nullable=False, index=True)
    image_id: Mapped[int] = mapped_column(Integer, ForeignKey("images.id"), nullable=False, index=True)

    algorithm:            Mapped[str]      = mapped_column(String(32),  nullable=False)
    key_hint:             Mapped[str|None] = mapped_column(String(16),  nullable=True)
    _metrics:             Mapped[str|None] = mapped_column("metrics",  Text, nullable=True)
    _metadata:            Mapped[str|None] = mapped_column("meta",     Text, nullable=True)
    encrypted_image_url:  Mapped[str|None] = mapped_column(String(512), nullable=True)
    encrypted_filename:   Mapped[str|None] = mapped_column(String(255), nullable=True)
    processing_time_ms:   Mapped[float|None] = mapped_column(Float, nullable=True)
    created_at:           Mapped[datetime]   = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user:  Mapped["User"]  = relationship(back_populates="results")
    image: Mapped["Image"] = relationship(back_populates="results")

    @property
    def metrics(self) -> dict:
        return json.loads(self._metrics) if self._metrics else {}

    @metrics.setter
    def metrics(self, v: dict) -> None:
        self._metrics = json.dumps(v)

    @property
    def metadata_dict(self) -> dict:
        return json.loads(self._metadata) if self._metadata else {}

    @metadata_dict.setter
    def metadata_dict(self, v: dict) -> None:
        self._metadata = json.dumps(v)

    def to_dict(self) -> dict:
        return {
            "id":                  self.id,
            "image_id":            self.image_id,
            "algorithm":           self.algorithm,
            "metrics":             self.metrics,
            "encrypted_image_url": self.encrypted_image_url,
            "processing_time_ms":  self.processing_time_ms,
            "created_at":          self.created_at.isoformat() if self.created_at else None,
        }
