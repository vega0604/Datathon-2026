"""SHE-46: checks on the KEV similarity feature in the real feature table. Skipped until
embeddings, similarity and features have been rebuilt."""

import json

import pytest

from backend.core.config import FEATURES_DIR, LOGS_DIR
from backend.db.warehouse import connect

FEATURES = f"read_parquet('{(FEATURES_DIR / 'features.parquet').as_posix()}')"
LOG = LOGS_DIR / "features_log.json"


def similarity_built() -> bool:
    if not (FEATURES_DIR / "similarity.parquet").exists() or not LOG.exists():
        return False
    return "after_similarity" in json.loads(LOG.read_text())


pytestmark = pytest.mark.skipif(
    not similarity_built(),
    reason="no similarity feature: run embeddings, then similarity, then features",
)


def test_row_counts_unchanged():
    log = json.loads(LOG.read_text())
    assert log["after_similarity"] == 136_790
    assert log["banned_columns"] == 0


def test_similarity_range():
    low, high = connect().execute(
        f"SELECT min(kev_sim_max), max(kev_sim_max) FROM {FEATURES}"
    ).fetchone()
    assert -1 <= low <= high <= 1


def test_report_positive_and_negative_means(capsys):
    """Reported, not asserted: mean kev_sim_max for positives vs negatives."""
    rows = connect().execute(
        f"""
        SELECT fold,
               avg(kev_sim_max) FILTER (WHERE label = 1),
               avg(kev_sim_max) FILTER (WHERE label = 0)
        FROM {FEATURES} WHERE fold IN (2024, 2025) GROUP BY fold ORDER BY fold
        """
    ).fetchall()
    with capsys.disabled():
        for fold, positives, negatives in rows:
            print(f"\nkev_sim_max {fold}: positives {positives:.4f}, negatives {negatives:.4f}")
    assert len(rows) == 2
