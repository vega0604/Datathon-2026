from datetime import date
from typing import Literal

from pydantic import BaseModel


class QueueItem(BaseModel):
    rank: int
    cvss_rank: int
    cve_id: str
    components: list[str]
    on_kev: bool
    kev_date_added: date | None = None
    known_ransomware: bool
    score: float | None = None
    epss: float | None = None
    exploit_code: bool
    cvss_score: float | None = None
    published: date | None = None
    version_status: Literal["in_range", "unverified"]
    description: str | None = None
    reasons: list[str] = []  # filled by SHE-56
    explanation: str | None = None  # filled by SHE-47


class QueueOut(BaseModel):
    sbom_id: str
    ranking: Literal["epss_placeholder", "model"]
    total: int
    items: list[QueueItem]
