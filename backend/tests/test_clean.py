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
