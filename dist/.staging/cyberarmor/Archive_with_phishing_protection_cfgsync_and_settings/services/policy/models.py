from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB

from db import Base


def now_utc():
    return datetime.now(timezone.utc)


class Policy(Base):
    __tablename__ = "policies"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    tenant_id = Column(String, nullable=False)
    version = Column(String, nullable=False)
    rules = Column(JSONB().with_variant(Text, "sqlite"), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
