from datetime import date
from typing import Literal

from pydantic import BaseModel


class QueueItem(BaseModel):
    rank: int
    cvss_rank: int
    cve_id: str
    components: list[str]
    match_methods: list[str] = []  # cpe, purl, name (+ _product_only), description
    on_kev: bool
    kev_date_added: date | None = None
    known_ransomware: bool
    # The submitted ranking's score (model + safety blend), comparable across all CVEs.
    score: float | None = None
    score_pct: float | None = None  # percentile among all scored vulnerabilities
    p_exploit: float | None = None  # model's chance of a KEV addition (rough, uncalibrated)
    model_pct: float | None = None
    confidence: Literal["exploited", "model"] | None = None
    basis: Literal["kev", "snapshot_2026", "latest_signals", "no_signals"] | None = None
    as_of: str | None = None  # month the scores describe, YYYY-MM
    stale: bool = False  # as_of is older than SCORE_STALE_DAYS
    similarity_used: bool | None = None
    epss: float | None = None
    exploit_code: bool
    cvss_score: float | None = None
    published: date | None = None
    version_status: Literal["in_range", "unverified"]
    granite_verdict: Literal["yes", "no", "unknown"] | None = None  # description matches only
    granite_reason: str | None = None
    epss_live: float | None = None  # EPSS_LIVE: today's EPSS from FIRST
    epss_live_pct: float | None = None
    epss_live_date: str | None = None
    score_live: float | None = None  # the score re-computed with today's EPSS
    description: str | None = None
    reasons: list[str] = []
    explanation: str | None = None  # filled by SHE-47


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
    total: int
    scores: ScoresInfo = ScoresInfo()
    items: list[QueueItem]
