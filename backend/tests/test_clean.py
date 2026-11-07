"""Unit tests for backend.clean on tiny in-memory tables. No real data needed."""

import duckdb
import pytest

from backend import clean


@pytest.fixture
def con():
    return duckdb.connect()


def rows(con, sql: str) -> list[tuple]:
    return con.execute(sql).fetchall()


# --- SHE-18 ---


def test_cwe_long(con):
    con.execute(
        """
        CREATE TABLE vulnerabilities AS SELECT * FROM (VALUES
            ('CVE-A', 'CWE-79;CWE-89'),
            ('CVE-B', ''),
            ('CVE-C', 'NVD-CWE-Other;NVD-CWE-noinfo'),
            ('CVE-D', NULL),
            ('CVE-E', 'CWE-22; CWE-22')
        ) AS t(cve_id, cwe_ids)
        """
    )
    assert rows(con, clean.cwe_long_sql()) == [
        ("CVE-A", "CWE-79"),
        ("CVE-A", "CWE-89"),
        ("CVE-B", "unknown"),
        ("CVE-C", "unknown"),
        ("CVE-D", "unknown"),
        ("CVE-E", "CWE-22"),
    ]


# --- SHE-19 ---


def test_drop_rejected(con):
    con.execute("CREATE TABLE vulnerabilities AS SELECT * FROM (VALUES ('CVE-A')) AS t(cve_id)")
    con.execute(
        "CREATE TABLE s AS SELECT * FROM (VALUES ('2025-01', 'CVE-A'), ('2025-01', 'CVE-X')) "
        "AS t(month, cve_id)"
    )
    assert rows(con, clean.drop_rejected_sql("s")) == [("2025-01", "CVE-A")]


# --- SHE-20 ---


def test_fill_feb_2025(con):
    # A: Jan + Mar, missing Feb -> filled. B: Jan only. C: all three months. D: no Jan.
    con.execute(
        """
        CREATE TABLE s AS SELECT * FROM (VALUES
            ('2025-01', 'CVE-A'), ('2025-03', 'CVE-A'),
            ('2025-01', 'CVE-B'),
            ('2025-01', 'CVE-C'), ('2025-02', 'CVE-C'), ('2025-03', 'CVE-C'),
            ('2025-02', 'CVE-D'), ('2025-03', 'CVE-D')
        ) AS t(month, cve_id)
        """
    )
    sql = clean.fill_feb_2025_sql("s")
    assert rows(con, f"SELECT month, cve_id FROM ({sql}) WHERE filled_gap = 1") == [
        ("2025-02", "CVE-A")
    ]
    assert rows(con, f"SELECT count(*) FROM ({sql})") == [(9,)]
