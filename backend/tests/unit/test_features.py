"""Unit tests for backend.pipeline.features on tiny tables. No real data needed."""

import duckdb
import pytest

from backend.pipeline import features


@pytest.fixture
def con():
    con = duckdb.connect()
    con.execute(
        """
        CREATE TABLE p AS SELECT * FROM (VALUES
            ('CVE-A', 2025, '2025-01', DATE '2025-01-31', DATE '2025-11-04'),
            ('CVE-B', 2025, '2025-01', DATE '2025-01-31', DATE '2025-11-04'),
            ('CVE-S', 2026, '2026-07', DATE '2026-07-31', DATE '2026-11-04')
        ) AS t(cve_id, fold, snapshot_month, snapshot_end, cutoff)
        """
    )
    return con


def rows(con, sql: str) -> list[tuple]:
    return con.execute(sql).fetchall()


# --- SHE-27 ---


def test_signals_at_snapshot(con):
    con.execute(
        """
        CREATE TABLE sig AS SELECT * FROM (VALUES
            ('CVE-A', '2025-01', 0.3::DOUBLE, 0, 1, 0, 0),
            ('CVE-A', '2025-02', 0.9::DOUBLE, 1, 1, 1, 1),
            ('CVE-B', '2025-02', 0.5::DOUBLE, 1, 0, 0, 0)
        ) AS t(cve_id, month, epss, exploitdb, metasploit, nuclei, poc_github)
        """
    )
    con.execute(
        """
        CREATE TABLE scoreboard_2026 AS SELECT * FROM (VALUES
            ('CVE-S', '2026-07', 0.7::DOUBLE, 0, 0, 0, 1)
        ) AS t(cve_id, snapshot_month, epss, exploitdb, metasploit, nuclei, poc_github)
        """
    )
    sql = features.signals_at_snapshot_sql("p", signals="sig")
    # A: its snapshot month only, never later. B: nothing at its snapshot -> NULL, 0.
    assert rows(
        con, f"SELECT cve_id, epss, metasploit, any_exploit_code FROM ({sql}) ORDER BY cve_id"
    ) == [("CVE-A", 0.3, 1, 1), ("CVE-B", None, 0, 0), ("CVE-S", 0.7, 0, 1)]


def test_epss_pct_within_fold_and_month(con):
    con.execute(
        """
        CREATE TABLE s AS SELECT * FROM (VALUES
            ('A', 2025, '2025-01', 0.1::DOUBLE),
            ('B', 2025, '2025-01', 0.9::DOUBLE),
            ('C', 2025, '2025-01', NULL::DOUBLE),
            ('D', 2026, '2025-01', 0.5::DOUBLE)
        ) AS t(cve_id, fold, snapshot_month, epss)
        """
    )
    result = dict(rows(con, f"SELECT cve_id, epss_pct FROM ({features.add_epss_pct_sql('s')})"))
    assert result == {"A": 0.0, "B": 1.0, "C": None, "D": 0.0}
