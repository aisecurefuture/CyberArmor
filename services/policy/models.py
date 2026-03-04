"""Enhanced Policy models with AND/OR conditions, action modes, and enable/disable."""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB

from db import Base


def now_utc():
    return datetime.now(timezone.utc)


class Policy(Base):
    __tablename__ = "policies"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    tenant_id = Column(String, nullable=False, index=True)
    version = Column(String, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    action = Column(String, default="monitor", nullable=False)  # monitor, block, warn, allow
    priority = Column(Integer, default=100, nullable=False)
    conditions = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    rules = Column(JSONB().with_variant(Text, "sqlite"), nullable=False)
    compliance_frameworks = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    tags = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    created_by = Column(String, nullable=True)
