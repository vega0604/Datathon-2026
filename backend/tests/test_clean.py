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


# --- SHE-21 ---


def test_epss_pct(con):
    con.execute(
        """
        CREATE TABLE s AS SELECT * FROM (VALUES
            ('2025-01', 'A', 0.1::DOUBLE),
            ('2025-01', 'B', 0.5::DOUBLE),
            ('2025-01', 'C', 0.9::DOUBLE),
            ('2025-01', 'D', NULL::DOUBLE),
            ('2025-02', 'E', 0.2::DOUBLE)
        ) AS t(month, cve_id, epss)
        """
    )
    result = dict(rows(con, f"SELECT cve_id, epss_pct FROM ({clean.add_epss_pct_sql('s')})"))
    assert result == {"A": 0.0, "B": 0.5, "C": 1.0, "D": None, "E": 0.0}


# --- SHE-22 ---


@pytest.mark.parametrize(
    ("name", "key"),
    [
        ("Palo Alto Networks", "paloaltonetworks"),
        ("paloaltonetworks", "paloaltonetworks"),
        ("TP-Link", "tplink"),
        ("tp-link", "tplink"),
        ("D-Link", "dlink"),
        ("Microsoft", "microsoft"),
    ],
)
def test_vendor_key(con, name, key):
    assert con.execute(f"SELECT {clean.vendor_key_sql('?')}", [name]).fetchone()[0] == key


def test_kev_vendor_key_uses_aliases(con):
    con.execute(
        """
        CREATE TABLE known_exploited AS SELECT * FROM (VALUES
            ('CVE-A', 'Android', DATE '2025-01-01'),
            ('CVE-B', 'Palo Alto Networks', DATE '2025-01-02')
        ) AS t(cve_id, vendor, date_added)
        """
    )
    con.execute(
        "CREATE TABLE vendor_aliases AS SELECT * FROM (VALUES ('Android', 'google')) "
        "AS t(kev_vendor, cpe_vendor)"
    )
    sql = clean.kev_with_vendor_key_sql()
    assert rows(con, f"SELECT cve_id, vendor_key FROM ({sql})") == [
        ("CVE-A", "google"),
        ("CVE-B", "paloaltonetworks"),
    ]


def test_vendor_aliases_derived_from_data(con):
    con.execute(
        """
        CREATE TABLE known_exploited AS SELECT * FROM (VALUES
            ('CVE-1', 'Android'), ('CVE-2', 'Android'),
            ('CVE-3', 'Palo Alto Networks'),
            ('CVE-4', 'Git'),
            ('CVE-5', 'Sudo'),
            ('CVE-6', 'WordPress'), ('CVE-7', 'WordPress')
        ) AS t(cve_id, vendor)
        """
    )
    con.execute(
        """
        CREATE TABLE affected_products AS SELECT * FROM (VALUES
            ('CVE-1', 'google', 'Y'), ('CVE-1', 'debian', 'Y'), ('CVE-2', 'google', 'Y'),
            ('CVE-3', 'paloaltonetworks', 'Y'),
            ('CVE-4', 'git-scm', 'Y'), ('CVE-4', 'apple', 'Y'),
            ('CVE-5', 'debian', 'Y'), ('CVE-5', 'debian', 'Y'), ('CVE-5', 'sudo_project', 'Y'),
            ('CVE-6', 'plugin_a', 'Y'), ('CVE-7', 'plugin_b', 'Y')
        ) AS t(cve_id, vendor, vulnerable)
        """
    )
    # Android: majority. Palo Alto: key already matches, no alias. Git: tie broken by name.
    # Sudo: debian ignored. WordPress: tied with no name match, so no alias.
    assert rows(con, f"SELECT kev_vendor, cpe_vendor FROM ({clean.vendor_aliases_sql()})") == [
        ("Android", "google"),
        ("Git", "git-scm"),
        ("Sudo", "sudo_project"),
    ]
