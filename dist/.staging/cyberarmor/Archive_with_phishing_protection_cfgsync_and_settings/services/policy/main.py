import logging
import os
import time
from datetime import datetime, timezone
from typing import Annotated,List
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import Base, SessionLocal, engine
from models import Policy



POLICY_API_SECRET = os.getenv("POLICY_API_SECRET", "change-me-policy")


def verify_api_key(api_key: Annotated[str | None, Header(alias="x-api-key")] = None):
    if api_key != POLICY_API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")

logger = logging.getLogger("policy_service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def init_db():
    Base.metadata.create_all(bind=engine)


def wait_for_db(max_wait_s: int = 45) -> None:
    """Block startup until Postgres is actually accepting connections."""
    start = time.time()
    attempt = 0
    while True:
        attempt += 1
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql("SELECT 1")
            return
        except Exception as e:
            elapsed = time.time() - start
            if elapsed >= max_wait_s:
                logger.error("db_not_ready_after_s=%s last_err=%s", int(elapsed), e)
                raise
            sleep_s = min(0.25 * (1.4 ** (attempt - 1)), 2.0)
            logger.warning("db_not_ready_yet sleep_s=%.2f err=%s", sleep_s, e)
            time.sleep(sleep_s)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class PolicyCreate(BaseModel):
    name: str
    tenant_id: str
    rules: dict

class PolicyOut(BaseModel):
    id: str
    name: str
    tenant_id: str
    version: str
    rules: dict

class Config:
    orm_mode = True


app = FastAPI(title="CyberArmor Policy Service", version="0.1.1")


@app.on_event("startup")
def on_startup():
    wait_for_db()
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}
# If you already have these models/types, reuse them.
# The important part is: return the policies for a tenant.
@app.get("/policies/{tenant_id}", response_model=List[PolicyOut])
def get_policies_for_tenant(tenant_id: str, db: Annotated[Session, Depends(get_db)], _: Annotated[None, Depends(verify_api_key)]):
    """
    Return all policies for a tenant (or the latest versions).
    """
    # If you store policies in a DB:
    rows = (db.query(Policy).filter(Policy.tenant_id == tenant_id).order_by(Policy.updated_at.desc()).all())
    
    # If you store policies in an in-memory dict keyed by tenant:
    # rows = POLICY_STORE.get(tenant_id, [])

    #rows = []  # <-- replace with your actual storage lookup
    if not rows:
        raise HTTPException(status_code=404, detail="Not Found")

    return rows


@app.get("/policies/{tenant_id}/{name}", response_model=PolicyOut)
def get_policy(tenant_id: str, name: str, db: Annotated[Session, Depends(get_db)], _: Annotated[None, Depends(verify_api_key)]):
    record = db.query(Policy).filter(Policy.tenant_id == tenant_id, Policy.name == name).first()
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    return record
@app.get("/policies/{tenant_id}/{policy_name}", response_model=PolicyOut)
def get_policy_by_name(
    tenant_id: str,
    policy_name: str,
    db: Session = Depends(get_db),):
    row = (
        db.query(Policy)
        .filter(Policy.tenant_id == tenant_id, Policy.name == policy_name)
        .order_by(Policy.updated_at.desc())
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Not Found")
    return row

@app.post("/policies", response_model=PolicyOut)
def upsert_policy(payload: PolicyCreate, db: Annotated[Session, Depends(get_db)], _: Annotated[None, Depends(verify_api_key)]):
    record = db.query(Policy).filter(Policy.tenant_id == payload.tenant_id, Policy.name == payload.name).first()
    version = f"v{int(datetime.utcnow().timestamp())}"
    if record:
        record.rules = payload.rules
        record.version = version
        record.updated_at = datetime.now(timezone.utc)
    else:
        record = Policy(
            id=str(uuid4()),
            name=payload.name,
            tenant_id=payload.tenant_id,
            version=version,
            rules=payload.rules,
        )
        db.add(record)
    db.commit()
    db.refresh(record)
    logger.info("policy updated tenant=%s name=%s version=%s", payload.tenant_id, payload.name, version)
    return record
