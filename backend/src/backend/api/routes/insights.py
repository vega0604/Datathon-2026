"""Benchmark-wide numbers for the Insights pages, the benchmark facts and the current user.

The Insights numbers are built offline (`uv run python -m backend.modeling.insights`) and
served from data/features/insights.json, so a request never trains or scores anything.
"""

import json
import logging
import threading

from fastapi import APIRouter, HTTPException

from backend.core import config

router = APIRouter(prefix="/api", tags=["insights"])
log = logging.getLogger(__name__)

NOT_BUILT = "The insights haven't been built yet. Run `uv run python -m backend.modeling.insights`."
BUILDING = "The insights are being built. This takes a few minutes; the page loads when ready."

_build = {"thread": None, "error": None}


def _run_build() -> None:
    try:
        from backend.db.warehouse import connect
        from backend.modeling.insights import write

        write(connect())
        log.info("built %s", config.INSIGHTS_PATH)
    except Exception as e:
        log.exception("building the insights failed")
        _build["error"] = f"Building the insights failed: {e}"


def build_if_missing() -> None:
    """Start building insights.json in the background when it doesn't exist (a fresh
    clone: data/ isn't in git). The routes answer 503 with BUILDING until it's written."""
    if config.INSIGHTS_PATH.exists() or _build["thread"] is not None:
        return
    _build["thread"] = threading.Thread(target=_run_build, name="build-insights", daemon=True)
    _build["thread"].start()


def _insights() -> dict:
    path = config.INSIGHTS_PATH
    if not path.exists():
        thread = _build["thread"]
        detail = (
            BUILDING if thread is not None and thread.is_alive() else _build["error"] or NOT_BUILT
        )
        raise HTTPException(status_code=503, detail=detail)
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
