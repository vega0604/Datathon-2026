from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Response, UploadFile

from backend.api.deps import Db
from backend.core import config
from backend.schemas.queue import QueueItem, QueueOut, StatusIn, TicketOut
from backend.schemas.sbom import SbomDetail, SbomOut, SbomSummary
from backend.services import sbom as sbom_service
from backend.services.components import components_view
from backend.services.description_match import match_descriptions
from backend.services.linear import LinearError, create_ticket, existing_ticket
from backend.services.match_verify import verify_description_matches
from backend.services.matching import match_sbom
from backend.services.queue import (
    DEFAULT_LIMIT,
    build_queue,
    forget,
    in_queue,
    predictions_source,
    queue_row,
    set_status,
)
from backend.services.sbom import MAX_BYTES, SbomError, SbomTooLarge

router = APIRouter(prefix="/api/sboms", tags=["sboms"])

NO_SBOM = "We couldn't find that SBOM."
NO_CVE = "That vulnerability isn't in this SBOM's queue."


def _ingest(file: UploadFile, db) -> str:
    """Parse (CycloneDX JSON or XML), store and match an uploaded SBOM; return its id."""
    raw = file.file.read(MAX_BYTES + 1)
    try:
        name, components, spec = sbom_service.parse_sbom(raw)
    except SbomTooLarge as e:
        raise HTTPException(status_code=413, detail=str(e)) from e
    except SbomError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    sbom_id = sbom_service.store_sbom(
        db, name or _stem(file.filename) or "SBOM", file.filename, components, spec
    )
    match_sbom(db, sbom_id)
    match_descriptions(db, sbom_id)  # vulnerabilities NIST hasn't analysed (no product list)
    if config.GRANITE_MATCH_CHECK:
        verify_description_matches(db, sbom_id, predictions=predictions_source())
    forget(sbom_id)  # a re-upload of the same file keeps its id
    return sbom_id


def _stem(filename: str | None) -> str | None:
    if not filename:
        return None
    stem = filename.rsplit("/", 1)[-1]
    for suffix in (".cdx.json", ".cdx.xml", ".json", ".xml"):
        if stem.lower().endswith(suffix):
            return stem[: -len(suffix)]
    return stem


def _need_sbom(db, sbom_id: str) -> None:
    if sbom_service.load_sbom(db, sbom_id) is None:
        raise HTTPException(status_code=404, detail=NO_SBOM)


@router.post("", status_code=201, response_model=SbomDetail)
def upload_sbom(file: UploadFile, db: Db):
    """Upload a CycloneDX SBOM; returns it with every component and its risk. An earlier
    upload with the same filename is replaced."""
    return components_view(db, _ingest(file, db))


@router.post("/fix-first", status_code=201, response_model=QueueOut)
def upload_and_rank(
    file: UploadFile,
    db: Db,
    limit: Annotated[int, Query(ge=1, le=DEFAULT_LIMIT)] = DEFAULT_LIMIT,
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
        raise HTTPException(status_code=404, detail=NO_SBOM)
    return sbom


@router.delete("/{sbom_id}", status_code=204)
def delete_sbom(sbom_id: str, db: Db):
    if not sbom_service.delete_sbom(db, sbom_id):
        raise HTTPException(status_code=404, detail=NO_SBOM)
    forget(sbom_id)
    return Response(status_code=204)


@router.get("/{sbom_id}/components", response_model=SbomDetail)
def get_components(sbom_id: str, db: Db):
    view = components_view(db, sbom_id)
    if view is None:
        raise HTTPException(status_code=404, detail=NO_SBOM)
    return view


@router.get("/{sbom_id}/queue", response_model=QueueOut)
def get_queue(
    sbom_id: str,
    db: Db,
    limit: Annotated[int, Query(ge=1, le=DEFAULT_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
    q: Annotated[str | None, Query(max_length=100)] = None,
    view: Literal["all", "critical", "not_in_linear", "warning_signs"] = "all",
    sort: Literal["rank", "cvss_desc", "cvss_asc"] = "rank",
):
    """A page of the queue. `q` searches CVE ids and component names, `view` is a filter
    chip, `sort` orders by CVSS (ties keep the rank); `matched` counts the selected rows."""
    _need_sbom(db, sbom_id)
    return build_queue(db, sbom_id, limit=limit, offset=offset, q=q, view=view, sort=sort)


def _row(db, sbom_id: str, cve_id: str) -> dict:
    row = queue_row(db, sbom_id, cve_id)
    if row is None:
        raise HTTPException(status_code=404, detail=NO_CVE)
    return row


@router.patch("/{sbom_id}/queue/{cve_id}", response_model=QueueItem)
def change_status(sbom_id: str, cve_id: str, body: StatusIn, db: Db):
    """Set a row's status (to_do, in_progress, done); returns the updated row."""
    _need_sbom(db, sbom_id)
    cve_id = cve_id.upper()
    if not in_queue(db, sbom_id, cve_id):
        raise HTTPException(status_code=404, detail=NO_CVE)
    set_status(db, sbom_id, cve_id, body.status)
    forget(sbom_id)
    return _row(db, sbom_id, cve_id)


@router.post("/{sbom_id}/queue/{cve_id}/linear", status_code=201, response_model=TicketOut)
def push_to_linear(sbom_id: str, cve_id: str, db: Db, response: Response):
    """Create a Linear issue for the row (once: a second call returns the same ticket)."""
    _need_sbom(db, sbom_id)
    cve_id = cve_id.upper()
    if not in_queue(db, sbom_id, cve_id):
        raise HTTPException(status_code=404, detail=NO_CVE)
    ticket = existing_ticket(db, sbom_id, cve_id)
    if ticket is not None:
        response.status_code = 200
        return {"ticket": ticket}
    try:
        ticket = create_ticket(db, sbom_id, _row(db, sbom_id, cve_id))
    except LinearError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    forget(sbom_id)
    return {"ticket": ticket}
