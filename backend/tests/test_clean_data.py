"""Checks on the real cleaned data in data/clean/ (SHE-18 to SHE-22).

Expected numbers were measured from the challenge data on 2026-11-07. Skipped
until `uv run python -m backend.clean` has run.
"""

import json

import pytest

from backend.core.config import LOGS_DIR
from backend.db.warehouse import connect

LOG_PATH = LOGS_DIR / "clean_log.json"

pytestmark = pytest.mark.skipif(
    not LOG_PATH.exists(), reason="no cleaned data: run `uv run python -m backend.clean` first"
)


@pytest.fixture(scope="module")
def con():
    return connect()


@pytest.fixture(scope="module")
def log():
    return json.loads(LOG_PATH.read_text())


def scalar(con, sql: str):
    return con.execute(sql).fetchone()[0]


# --- SHE-18 ---


def test_cwe(con):
    assert scalar(con, "SELECT count(*) FROM clean.cwe") == 441_086
    assert scalar(con, "SELECT count(DISTINCT cve_id) FROM clean.cwe") == 401_082
    assert scalar(con, "SELECT count(*) FROM clean.cwe WHERE cwe_id = 'unknown'") == 61_297


# --- SHE-19 ---


def test_rejected_ids_dropped(con, log):
    assert log["signals_raw"] == 6_463_734
    assert log["signals_after_drop_rejected"] == 6_312_757  # 150,977 rows, 11,793 IDs
    orphans = """
        SELECT count(*) FROM clean.exploit_signals
        WHERE cve_id NOT IN (SELECT cve_id FROM vulnerabilities)
    """
    assert scalar(con, orphans) == 0


# --- SHE-20 ---


def test_feb_2025_filled(con, log):
    assert log["signals_after_fill_feb_2025"] == 6_327_309  # + 14,552 filled rows
    assert scalar(con, "SELECT sum(filled_gap) FROM clean.exploit_signals") == 14_552
    feb = "SELECT count(*) FROM clean.exploit_signals WHERE month = '2025-02'"
    assert scalar(con, feb) == 267_661
    duplicates = """
        SELECT count(*) FROM (
            SELECT month, cve_id FROM clean.exploit_signals GROUP BY ALL HAVING count(*) > 1
        )
    """
    assert scalar(con, duplicates) == 0


# --- SHE-21 ---


def test_epss_pct(con, log):
    assert log["signals_after_epss_pct"] == 6_327_309  # adds a column, not rows
    low, high, missing, epss_missing = con.execute(
        """
        SELECT min(epss_pct), max(epss_pct), count(*) FILTER (WHERE epss_pct IS NULL),
               count(*) FILTER (WHERE epss IS NULL)
        FROM clean.exploit_signals
        """
    ).fetchone()
    assert (low, high) == (0.0, 1.0)
    assert missing == epss_missing == 302


# --- SHE-22 ---


def test_vendor_keys(con, log):
    assert log["vendor_aliases"] == 47
    assert log["kev"] == 1_484
    assert log["affected_products"] == 3_155_934
    # 1,365 KEV rows match by key alone; the derived aliases bring it to 1,454.
    assert log["kev_vendor_matches"] == 1_454
    assert scalar(con, "SELECT count(*) FROM clean.kev WHERE vendor_key = ''") == 0
    aliases = dict(
        con.execute("SELECT kev_vendor, cpe_vendor FROM clean.vendor_aliases").fetchall()
    )
    assert aliases["Android"] == "google"
    assert aliases["Zoho"] == "zohocorp"
