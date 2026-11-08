"""Unit tests for backend.pipeline.population on tiny tables. No real data needed."""

from datetime import date

import duckdb
import pytest

from backend.pipeline import population


@pytest.fixture
def con():
    con = duckdb.connect()
    con.execute(
        """
        CREATE TABLE vulnerabilities AS SELECT * FROM (VALUES
            ('CVE-A', DATE '2025-01-15'),
            ('CVE-B', DATE '2025-09-30'),
            ('CVE-C', DATE '2025-10-01'),
            ('CVE-D', DATE '2023-05-01')
        ) AS t(cve_id, published)
        """
    )
    con.execute(
        "CREATE TABLE scoreboard_2026 AS SELECT * FROM (VALUES "
        "('CVE-S', DATE '2026-06-10', '2026-07')) AS t(cve_id, published, snapshot_month)"
    )
    return con


def rows(con, sql: str) -> list[tuple]:
    return con.execute(sql).fetchall()


# --- SHE-24 ---


def test_snapshot_month_rule(con):
    sql = population.snapshot_month_sql("d")
    result = rows(
        con, f"SELECT {sql} FROM (VALUES (DATE '2026-06-10'), (DATE '2025-02-01')) AS t(d)"
    )
    assert result == [("2026-07",), ("2025-02",)]


def test_candidates(con):
    sql = population.candidates_sql()
    result = rows(
        con,
        f"SELECT cve_id, fold, snapshot_month, snapshot_end, cutoff FROM ({sql}) ORDER BY cve_id",
    )
    assert result == [
        ("CVE-A", 2025, "2025-01", date(2025, 1, 31), date(2025, 11, 4)),
        ("CVE-B", 2025, "2025-09", date(2025, 9, 30), date(2025, 11, 4)),
        ("CVE-S", 2026, "2026-07", date(2026, 7, 31), date(2026, 11, 4)),
    ]


# --- SHE-25 ---


def test_drop_already_exploited(con):
    con.execute(f"CREATE TABLE c AS {population.candidates_sql()}")
    con.execute(
        """
        CREATE TABLE known_exploited AS SELECT * FROM (VALUES
            ('CVE-A', DATE '2025-01-31'),
            ('CVE-B', DATE '2025-10-01'),
            ('CVE-S', DATE '2026-01-01')
        ) AS t(cve_id, date_added)
        """
    )
    sql = population.drop_already_exploited_sql("c")
    # A: on KEV by its snapshot end -> dropped. B: added later -> kept. S: benchmark -> kept.
    assert rows(con, f"SELECT cve_id FROM ({sql}) ORDER BY cve_id") == [("CVE-B",), ("CVE-S",)]


# --- SHE-26 ---


def test_labels(con):
    con.execute(f"CREATE TABLE c AS {population.candidates_sql()}")
    con.execute(
        """
        CREATE TABLE known_exploited AS SELECT * FROM (VALUES
            ('CVE-A', DATE '2025-11-04'),
            ('CVE-B', DATE '2025-11-05')
        ) AS t(cve_id, date_added)
        """
    )
    sql = population.add_labels_sql("c")
    # A: added on the cutoff day -> 1. B: the day after -> 0. S: benchmark -> NULL.
    assert rows(con, f"SELECT cve_id, label FROM ({sql}) ORDER BY cve_id") == [
        ("CVE-A", 1),
        ("CVE-B", 0),
        ("CVE-S", None),
    ]
