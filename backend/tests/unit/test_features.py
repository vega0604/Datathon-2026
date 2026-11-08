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


# --- SHE-28 ---


def test_exposure(con):
    result = dict(
        rows(con, f"SELECT cve_id, days_to_cutoff FROM ({features.add_exposure_sql('p')})")
    )
    assert result == {"CVE-A": 277, "CVE-B": 277, "CVE-S": 96}


# --- SHE-29 ---


@pytest.fixture
def history(con):
    con.execute(
        """
        CREATE TABLE vulnerabilities AS SELECT * FROM (VALUES
            ('CVE-X1', 'psirt@x', DATE '2024-01-10'),
            ('CVE-X2', 'psirt@x', DATE '2024-06-01'),
            ('CVE-X3', 'psirt@x', DATE '2024-09-01'),
            ('CVE-A', 'psirt@x', DATE '2025-01-15'),
            ('CVE-B', 'cna@other', DATE '2025-01-20'),
            ('CVE-S', 'psirt@x', DATE '2026-06-10')
        ) AS t(cve_id, assigner, published)
        """
    )
    con.execute(
        """
        CREATE TABLE known_exploited AS SELECT * FROM (VALUES
            ('CVE-X1', DATE '2024-03-01'),
            ('CVE-X2', DATE '2025-01-31'),
            ('CVE-X3', DATE '2025-02-01')
        ) AS t(cve_id, date_added)
        """
    )
    return con


def test_assigner_history(history):
    sql = features.add_assigner_history_sql("p")
    result = rows(
        history,
        f"SELECT cve_id, assigner_kev_prior, assigner_cves_prior, assigner_kev_rate FROM ({sql}) "
        "ORDER BY cve_id",
    )
    # A (snapshot end 2025-01-31): X1 and X2 are on KEV by then; X3 only the next day.
    # 4 vulnerabilities from psirt@x were published by then (X1, X2, X3, A).
    assert result == [
        ("CVE-A", 2, 4, 0.5),
        ("CVE-B", 0, 1, 0.0),
        ("CVE-S", 3, 5, 0.6),
    ]


# --- SHE-30 ---


def test_assigner_history_ignores_the_future(history):
    # A KEV entry added after every snapshot, and a vulnerability published after it,
    # must not change any count.
    before = rows(
        history, f"SELECT * FROM ({features.add_assigner_history_sql('p')}) ORDER BY cve_id"
    )
    history.execute("INSERT INTO known_exploited VALUES ('CVE-A', DATE '2027-01-01')")
    history.execute("INSERT INTO vulnerabilities VALUES ('CVE-Z', 'psirt@x', DATE '2027-01-01')")
    after = rows(
        history, f"SELECT * FROM ({features.add_assigner_history_sql('p')}) ORDER BY cve_id"
    )
    assert after == before
