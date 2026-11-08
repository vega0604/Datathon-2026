"""Unit tests for backend.modeling.evaluate on a tiny fold. No real data needed."""

import duckdb
import pytest

from backend.modeling import evaluate as ev


@pytest.fixture
def con():
    con = duckdb.connect()
    # Ten vulnerabilities in fold 2025; CVE-01 and CVE-07 were exploited.
    con.execute(
        """
        CREATE TABLE pop AS
        SELECT printf('CVE-%02d', i) AS cve_id, 2025 AS fold,
               CASE WHEN i IN (1, 7) THEN 1 ELSE 0 END AS label,
               11 - i AS score
        FROM range(1, 11) AS t(i)
        """
    )
    return con


def test_scaled_k():
    assert ev.scaled_k(72_670) == 500
    assert ev.scaled_k(35_281) == 243
    assert ev.scaled_k(28_839) == 198


def test_evaluate_counts_hits(con):
    ranking = ev.ranked_sql("pop", 2025, "score DESC")  # CVE-01 first, CVE-10 last
    result = ev.evaluate(con, 2025, ranking, population="pop", k=3)
    assert result["rows"] == 10
    assert result["positives"] == 2
    assert result["hits_at_k"] == 1  # only CVE-01 is in the top 3
    assert result["hits_at_500"] == 2
    assert result["recall_at_k"] == 0.5


def test_ties_broken_by_cve_id(con):
    ranking = ev.ranked_sql("pop", 2025, "0")  # every score tied
    first = con.execute(f"SELECT cve_id FROM ({ranking}) WHERE rank = 1").fetchone()[0]
    assert first == "CVE-01"


def test_ranking_must_cover_the_fold(con):
    partial = "SELECT cve_id, 1 AS rank FROM pop WHERE cve_id = 'CVE-01'"
    with pytest.raises(ValueError, match="covers 1"):
        ev.evaluate(con, 2025, partial, population="pop")
