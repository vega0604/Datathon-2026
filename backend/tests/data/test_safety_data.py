"""SHE-48: the safety ranker's chosen weights and hits are logged and reproducible."""

import json

import pytest

from backend.core.config import LOGS_DIR
from backend.db.warehouse import connect
from backend.modeling import safety

LOG = LOGS_DIR / "safety_log.json"

pytestmark = pytest.mark.skipif(
    not LOG.exists(), reason="no safety log: run `uv run python -m backend.modeling.safety`"
)


def test_choice_is_logged_and_reproducible():
    log = json.loads(LOG.read_text())
    results = safety.run_grid(connect())
    best = safety.choose(results)
    assert log["chosen"] == {"w_code": best["w_code"], "w_vendor": best["w_vendor"]}
    assert log["chosen"] == {"w_code": safety.W_CODE, "w_vendor": safety.W_VENDOR}
    assert log["fold_2024"]["hits_at_k"] == best["hits_at_k"]
    assert log["fold_2024"]["hits_at_500"] == best["hits_at_500"]
    report = next(
        r
        for r in results
        if r["fold"] == 2025 and (r["w_code"], r["w_vendor"]) == (safety.W_CODE, safety.W_VENDOR)
    )
    assert log["fold_2025"]["hits_at_k"] == report["hits_at_k"]
    assert log["fold_2025"]["hits_at_500"] == report["hits_at_500"]
