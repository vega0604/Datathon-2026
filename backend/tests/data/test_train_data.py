"""SHE-51: the backtest log holds all 5 seeds and the ensemble for both protocols."""

import json

import pytest

from backend.core.config import LOGS_DIR

LOG = LOGS_DIR / "train_log.json"
SAFETY_LOG = LOGS_DIR / "safety_log.json"

pytestmark = pytest.mark.skipif(
    not LOG.exists(), reason="no train log: run `uv run python -m backend.modeling.train`"
)


def test_backtest_log_is_complete():
    log = json.loads(LOG.read_text())
    assert set(log["protocols"]) == {"primary", "time_reversed"}
    for name, test_fold, k in (("primary", 2025, 243), ("time_reversed", 2024, 198)):
        result = log["protocols"][name]
        assert result["test_fold"] == test_fold
        assert result["k"] == k
        assert [r["seed"] for r in result["per_seed"]] == [0, 1, 2, 3, 4]
        assert {"hits_at_k", "hits_at_500"} <= result["ensemble"].keys()
        assert result["hits_at_k"]["min"] <= result["hits_at_k"]["mean"] <= result["hits_at_k"]["max"]


def test_report_ensemble_against_the_safety_ranker(capsys):
    """Reported, not asserted."""
    ensemble = json.loads(LOG.read_text())["protocols"]["primary"]["ensemble"]["hits_at_k"]
    if SAFETY_LOG.exists():
        safety = json.loads(SAFETY_LOG.read_text())["fold_2025"]["hits_at_k"]
        with capsys.disabled():
            print(f"\n2025 hits@243: ensemble {ensemble}, safety ranker {safety}")
