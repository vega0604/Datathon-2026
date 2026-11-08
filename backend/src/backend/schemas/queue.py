from datetime import date
from typing import Literal

from pydantic import BaseModel

Severity = Literal["critical", "high", "medium", "low", "none"]
Status = Literal["to_do", "in_progress", "done"]


class Reason(BaseModel):
    kind: Literal["exploit", "exposure", "vendor"]
    label: str  # under 45 characters
    value: float  # signed SHAP contribution (log-odds)


class Ticket(BaseModel):
    id: str
    url: str | None = None


class QueueItem(BaseModel):
    # The table
    rank: int
    cve_id: str
    component: str  # one short display name
    components: list[str]
    score: float | None = None  # submitted ranking's score, 0-1, comparable across CVEs
    cvss_score: float  # 0 when NVD has no CVSS (severity "none")
    severity: Severity
    cvss_rank: int
    signal: Literal["exploit_code", "vendor_attacked", "score_jump"] | None = None
    status: Status = "to_do"
    ticket: Ticket | None = None
    # The detail panel
    vendor_initials: str | None = None
    subtitle: str | None = None
    explanation: str
    explanation_source: Literal["granite", "nvd"]
    reasons: list[Reason] = []
    reasons_are_sample: bool = False
    on_kev: bool
    kev_date_added: date | None = None
    kev_name: str | None = None
    known_ransomware: bool
    cwe_id: str | None = None
    cwe_name: str | None = None
    epss: float | None = None
    exploit_code: bool
    published: date | None = None
    description: str | None = None
    # Matching and scoring details
    match_methods: list[str] = []  # cpe, purl, name (+ _product_only), description
    version_status: Literal["in_range", "unverified"]
    granite_verdict: Literal["yes", "no", "unknown"] | None = None
    granite_reason: str | None = None
    score_pct: float | None = None
    p_exploit: float | None = None
    model_pct: float | None = None
    confidence: Literal["exploited", "model"] | None = None
    basis: Literal["kev", "snapshot_2026", "latest_signals", "no_signals"] | None = None
    as_of: str | None = None  # month the scores describe, YYYY-MM
    stale: bool = False
    similarity_used: bool | None = None
    epss_live: float | None = None
    epss_live_pct: float | None = None
    epss_live_date: str | None = None
    score_live: float | None = None


class Counts(BaseModel):
    open: int
    critical: int
    not_in_linear: int
    warning_signs: int


class ScoresInfo(BaseModel):
    variant: str | None = None
    alpha: float | None = None
    built_at: str | None = None
    signals_through: str | None = None
    scoreboard_months: list[str] | None = None
    refresh: str | None = None


class QueueOut(BaseModel):
    sbom_id: str
    ranking: Literal["epss_placeholder", "model", "model_live_epss"]
    total: int  # rows in the whole queue
    matched: int  # rows the search / filter selects (= total without one)
    counts: Counts
    scores: ScoresInfo = ScoresInfo()
    items: list[QueueItem]


class StatusIn(BaseModel):
    status: Status


class TicketOut(BaseModel):
    ticket: Ticket
