"""SHE-112: long training labels have at least as many positives as the benchmark."""

import json

import pytest

from backend.core.config import LOGS_DIR

LOG = LOGS_DIR / "labels_log.json"

pytestmark = pytest.mark.skipif(
    not LOG.exists(), reason="no labels log: run `uv run python -m backend.modeling.comparison`"
)


def test_long_positives_at_least_benchmark():
    log = json.loads(LOG.read_text())
    assert log["2024"]["benchmark"] == 27
    assert log["2025"]["benchmark"] == 48
    for fold, counts in log.items():
        longs = {k: v for k, v in counts.items() if k.startswith("long_")}
        assert longs, fold
        assert all(v >= counts["benchmark"] for v in longs.values()), (fold, counts)
