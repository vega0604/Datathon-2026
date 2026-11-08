"""SHE-36: the README baselines on the backtest folds. Expected numbers were measured
from the challenge data on 2026-11-07."""

import pytest

from backend.core.config import FEATURES_DIR
from backend.db.warehouse import connect
from backend.modeling.baselines import run_baselines

pytestmark = pytest.mark.skipif(
    not (FEATURES_DIR / "features.parquet").exists(),
    reason="no features: run `uv run python -m backend.pipeline.features` first",
)

# (fold, ranking) -> (hits at scaled K, hits at 500)
EXPECTED = {
    (2024, "cvss_first"): (2, 3),
    (2024, "epss_first"): (3, 4),
    (2024, "exploit_then_epss"): (6, 8),
    (2025, "cvss_first"): (8, 8),
    (2025, "epss_first"): (8, 8),
    (2025, "exploit_then_epss"): (13, 17),
}


def test_baselines():
    results = {(r["fold"], r["ranking"]): r for r in run_baselines(connect())}
    assert {key: (r["hits_at_k"], r["hits_at_500"]) for key, r in results.items()} == EXPECTED
    assert results[(2024, "epss_first")]["k"] == 198
    assert results[(2025, "epss_first")]["k"] == 243
