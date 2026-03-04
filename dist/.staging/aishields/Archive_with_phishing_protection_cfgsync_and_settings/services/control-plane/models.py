from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB

from db import Base


def now_utc():
    return datetime.now(timezone.utc)


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class ApiKey(Base):
    __tablename__ = "api_keys"
    key = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=True)
    role = Column(String, default="analyst")
    active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String, nullable=True)
    principal = Column(String, nullable=True)
    path = Column(String, nullable=False)
    method = Column(String, nullable=False)
    status = Column(String, nullable=False)
    duration_s = Column(String, nullable=False)
    meta = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
