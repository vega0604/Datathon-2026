from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel


class Component(BaseModel):
    component_id: int
    name: str
    group: str | None = None
    version: str | None = None
    purl: str | None = None
    cpe: str | None = None
    vendor: str | None = None
    product: str | None = None


class SbomSummary(BaseModel):
    sbom_id: str
    name: str | None
    filename: str | None
    uploaded_at: datetime
    component_count: int


class SbomOut(SbomSummary):
    components: list[Component]


Severity = Literal["critical", "high", "medium", "low", "none"]


class KevEntry(BaseModel):
    cve_id: str
    date_added: date | None = None
    name: str | None = None


class TopKev(BaseModel):
    date_added: date | None = None
    name: str | None = None
    ransomware: bool


class TopCve(BaseModel):
    cve_id: str
    cvss: float
    severity: Severity
    published: date | None = None
    summary: str | None = None
    epss: float | None = None
    kev: TopKev | None = None


class Risk(BaseModel):
    cve_count: int
    severity: dict[Severity, int]
    max_cvss: float
    epss_max: float | None = None
    fixed_in: str | None = None
    kev: list[KevEntry] = []
    top: list[TopCve] = []


class ComponentRisk(BaseModel):
    component_id: int
    name: str
    version: str | None = None
    vendor: str | None = None  # display name ("Palo Alto Networks"), not the CPE id
    cpe: str | None = None
    purl: str | None = None
    part: Literal["application", "operating system", "hardware"] | None = None
    rank: int  # by the component's highest-ranked CVE
    risk: Risk | None = None


class SbomDetail(SbomSummary):
    spec_version: str | None = None
    risk_checked: date
    components: list[ComponentRisk]
