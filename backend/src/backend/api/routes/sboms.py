from fastapi import APIRouter, HTTPException, UploadFile

from backend.api.deps import Db
from backend.schemas.sbom import SbomComponentsOut, SbomOut, SbomSummary
from backend.services import sbom as sbom_service
from backend.services.matching import match_sbom
from backend.services.sbom import MAX_BYTES, SbomError

router = APIRouter(prefix="/api/sboms", tags=["sboms"])


@router.post("", status_code=201, response_model=SbomOut)
def upload_sbom(file: UploadFile, db: Db):
    raw = file.file.read(MAX_BYTES + 1)
    try:
        name, components = sbom_service.parse_cyclonedx(raw)
    except SbomError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    sbom_id = sbom_service.store_sbom(
        db, name or file.filename or "SBOM", file.filename, components
    )
    match_sbom(db, sbom_id)
    return sbom_service.load_sbom(db, sbom_id)


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
