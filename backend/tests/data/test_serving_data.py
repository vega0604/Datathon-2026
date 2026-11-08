"""predictions.parquet scores every vulnerability on one scale (SHE-110, revised)."""

import pytest

from backend.db.warehouse import connect
from backend.modeling.serving import OUTPUT

pytestmark = pytest.mark.skipif(
    not OUTPUT.exists(), reason="no predictions: run `uv run python -m backend.modeling.serving`"
)
P = f"read_parquet('{OUTPUT.as_posix()}')"


@pytest.fixture(scope="module")
def con():
    return connect()


def test_one_row_per_vulnerability(con):
    rows, distinct = con.execute(f"SELECT count(*), count(DISTINCT cve_id) FROM {P}").fetchone()
    expected = con.execute("SELECT count(DISTINCT cve_id) FROM vulnerabilities").fetchone()[0]
    assert rows == distinct == expected


def test_groups_and_basis(con):
    groups = dict(con.execute(f"SELECT confidence, count(*) FROM {P} GROUP BY 1").fetchall())
    assert groups["exploited"] == 1_484
    assert set(groups) == {"exploited", "model"}
    board = con.execute(
        f"""
        SELECT count(*) FROM scoreboard_2026 AS s JOIN {P} AS p USING (cve_id)
        WHERE p.basis <> 'snapshot_2026'
        """
    ).fetchone()[0]
    assert board == 0  # no scoreboard vulnerability is on KEV


def test_every_vulnerability_has_a_score(con):
    nulls, low, high = con.execute(
        f"SELECT count(*) FILTER (WHERE score IS NULL), min(score_pct), max(score_pct) FROM {P}"
    ).fetchone()
    assert nulls == 0
    assert 0 < low <= high <= 1
