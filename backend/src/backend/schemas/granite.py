"""SHE-38: what Granite answers when asked whether a component is affected."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator

MAX_REASON_WORDS = 25


class MatchVerdict(BaseModel):
    affected: Literal["yes", "no", "unknown"]
    vendor: str | None = Field(None, description="Vendor the description says is affected")
    product: str | None = Field(None, description="Product the description says is affected")
    versions: str | None = Field(None, description="Affected versions or ranges, as written")
    confidence: Literal["low", "medium", "high"]
    reason: str = Field(description=f"{MAX_REASON_WORDS} words or fewer")
    error: bool = Field(False, description="True when the model never gave valid JSON")

    @field_validator("reason")
    @classmethod
    def short_reason(cls, value: str) -> str:
        """Cut a long reason instead of rejecting it: a retry costs tokens."""
        return " ".join(value.split()[:MAX_REASON_WORDS])
