"""Benchmark-wide numbers for the Insights pages, the benchmark facts and the current user.

The Insights numbers are built offline (`uv run python -m backend.modeling.insights`) and
served from data/features/insights.json, so a request never trains or scores anything.
"""

import json

from fastapi import APIRouter, HTTPException

from backend.core import config

router = APIRouter(prefix="/api", tags=["insights"])

NOT_BUILT = "The insights haven't been built yet."


def _insights() -> dict:
    path = config.INSIGHTS_PATH
    if not path.exists():
        raise HTTPException(status_code=503, detail=NOT_BUILT)
    return json.loads(path.read_text(encoding="utf-8"))


@router.get("/insights/summary")
def summary():
    return _insights()["summary"]


@router.get("/insights/catch-rate")
def catch_rate():
    return _insights()["catch_rate"]


@router.get("/insights/vendors")
def vendors():
    return _insights()["vendors"]


@router.get("/benchmark")
def benchmark():
    facts = _insights()["benchmark"]
    top500 = config.OUTPUTS_DIR / "top500.csv"
    facts["top_n_ready"] = bool(facts.get("top_n_ready")) and top500.exists()
    return facts


@router.get("/me")
def me():
    """The signed-in user. There is no login yet: the name comes from backend/.env."""
    return {"name": config.ME_NAME, "role": config.ME_ROLE, "avatar_url": config.ME_AVATAR_URL}
