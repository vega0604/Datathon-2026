"""SHE-110: predictions.parquet covers every vulnerability with the right groups."""

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


def test_groups(con):
    assert con.execute(f"SELECT count(*) FROM {P} WHERE confidence = 'exploited'").fetchone()[0] == 1_484
    not_model = con.execute(
        f"""
        SELECT count(*) FROM scoreboard_2026 AS s JOIN {P} AS p USING (cve_id)
        WHERE p.confidence <> 'model'
          AND s.cve_id NOT IN (SELECT cve_id FROM clean.kev)
        """
    ).fetchone()[0]
    assert not_model == 0
    assert {r[0] for r in con.execute(f"SELECT DISTINCT confidence FROM {P}").fetchall()} == {
        "exploited", "model", "lower",
    }  # fmt: skip


def test_percentiles_within_groups(con):
    low, high = con.execute(f"SELECT min(score_pct), max(score_pct) FROM {P}").fetchone()
    assert 0 <= low <= high <= 1
    nulls = con.execute(
        f"SELECT count(*) FROM {P} WHERE (score_raw IS NULL) <> (score_pct IS NULL)"
    ).fetchone()[0]
    assert nulls == 0
