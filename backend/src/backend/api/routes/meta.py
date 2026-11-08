from fastapi import APIRouter

from backend.api.deps import Db
from backend.core import config

router = APIRouter(prefix="/api")


@router.get("/meta")
def meta(db: Db) -> dict:
    n = db.execute("SELECT count(*) FROM vulnerabilities").fetchone()[0]
    return {"data_backend": config.DATA_BACKEND, "vulnerabilities": n}
