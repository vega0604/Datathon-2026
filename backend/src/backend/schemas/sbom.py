from datetime import datetime

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


class ComponentSummary(Component):
    matched_cves: int
    kev_cves: int


class SbomComponentsOut(BaseModel):
    sbom_id: str
    name: str | None
    components: list[ComponentSummary]
