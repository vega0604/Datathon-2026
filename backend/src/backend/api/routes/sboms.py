from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, UploadFile

from backend.api.deps import Db
from backend.core import config
from backend.schemas.queue import QueueOut
from backend.schemas.sbom import SbomComponentsOut, SbomOut, SbomSummary
from backend.services import sbom as sbom_service
from backend.services.description_match import match_descriptions
from backend.services.match_verify import verify_description_matches
from backend.services.matching import match_sbom
from backend.services.queue import build_queue, predictions_source
from backend.services.sbom import MAX_BYTES, SbomError

router = APIRouter(prefix="/api/sboms", tags=["sboms"])


def _ingest(file: UploadFile, db) -> str:
    """Parse, store and match an uploaded CycloneDX SBOM; return its id."""
    raw = file.file.read(MAX_BYTES + 1)
    try:
        name, components = sbom_service.parse_cyclonedx(raw)
    except SbomError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    sbom_id = sbom_service.store_sbom(
        db, name or file.filename or "SBOM", file.filename, components
    )
    match_sbom(db, sbom_id)
    match_descriptions(db, sbom_id)  # vulnerabilities NIST hasn't analysed (no product list)
    if config.GRANITE_MATCH_CHECK:
        verify_description_matches(db, sbom_id, predictions=predictions_source())
    return sbom_id


@router.post("", status_code=201, response_model=SbomOut)
def upload_sbom(file: UploadFile, db: Db):
    return sbom_service.load_sbom(db, _ingest(file, db))


@router.post("/fix-first", status_code=201, response_model=QueueOut)
def upload_and_rank(
    file: UploadFile,
    db: Db,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
):
    """Upload an SBOM and get its Fix-First queue in one request."""
    return build_queue(db, _ingest(file, db), limit=limit)


@router.get("", response_model=list[SbomSummary])
def list_sboms(db: Db):
    return sbom_service.list_sboms(db)


@router.get("/{sbom_id}", response_model=SbomOut)
def get_sbom(sbom_id: str, db: Db):
    sbom = sbom_service.load_sbom(db, sbom_id)
    if sbom is None:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return sbom


@router.get("/{sbom_id}/components", response_model=SbomComponentsOut)
def get_components(sbom_id: str, db: Db):
    sbom = sbom_service.load_sbom(db, sbom_id)
    if sbom is None:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return {
        "sbom_id": sbom_id,
        "name": sbom["name"],
        "components": sbom_service.component_summaries(db, sbom_id),
    }


@router.get("/{sbom_id}/queue", response_model=QueueOut)
def get_queue(
    sbom_id: str,
    db: Db,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if sbom_service.load_sbom(db, sbom_id) is None:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return build_queue(db, sbom_id, limit=limit, offset=offset)
