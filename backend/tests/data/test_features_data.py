"""Checks on the real feature table (SHE-27 to SHE-34). Expected numbers were measured
from the challenge data on 2026-11-07. Skipped until the features have been built."""

import json

import pytest

from backend.core.config import FEATURES_DIR, LOGS_DIR
from backend.db.warehouse import connect

LOG_PATH = LOGS_DIR / "features_log.json"
FEATURES = f"read_parquet('{(FEATURES_DIR / 'features.parquet').as_posix()}')"

pytestmark = pytest.mark.skipif(
    not LOG_PATH.exists(),
    reason="no features: run `uv run python -m backend.pipeline.features` first",
)


@pytest.fixture(scope="module")
def con():
    return connect()


@pytest.fixture(scope="module")
def log():
    return json.loads(LOG_PATH.read_text())


def by_fold(con, expression: str) -> tuple:
    sql = f"SELECT fold, {expression} FROM {FEATURES} GROUP BY fold ORDER BY fold"
    return tuple(value for _, value in con.execute(sql).fetchall())


# --- SHE-27 ---


def test_every_step_keeps_one_row_per_vulnerability(log):
    steps = {name: rows for name, rows in log.items() if name.startswith("after_")}
    assert steps and all(rows == 136_790 for rows in steps.values())


def test_signals(con):
    assert by_fold(con, "count(*) FILTER (WHERE epss IS NULL)") == (1_282, 3_460, 1_431)
    assert by_fold(con, "sum(any_exploit_code)") == (633, 761, 1_645)
    assert by_fold(con, "min(epss_pct)") == (0.0, 0.0, 0.0)
    assert by_fold(con, "max(epss_pct)") == (1.0, 1.0, 1.0)


# --- SHE-28 ---


def test_exposure(con):
    low, high = con.execute(
        f"SELECT min(days_to_cutoff), max(days_to_cutoff) FROM {FEATURES}"
    ).fetchone()
    assert (low, high) == (35, 278)  # September snapshots to January 2024 (a leap year)


# --- SHE-29 ---


def test_assigner_history(con):
    assert con.execute(f"SELECT count(*) FROM {FEATURES} WHERE assigner IS NULL").fetchone()[0] == 0
    pos, neg = con.execute(
        f"""
        SELECT avg(assigner_kev_prior) FILTER (WHERE label = 1),
               avg(assigner_kev_prior) FILTER (WHERE label = 0)
        FROM {FEATURES} WHERE fold = 2025
        """
    ).fetchone()
    assert pos > 1.5 * neg  # measured: about 80 vs 44


# --- SHE-30 ---


def test_assigner_history_matches_a_plain_recount(con):
    # Recount about 1 in 500 rows with an obviously correct (slow) query.
    mismatches = f"""
        SELECT count(*) FROM {FEATURES} AS f
        WHERE hash(f.cve_id) % 500 = 0
          AND f.assigner_kev_prior <> (
              SELECT count(*) FROM known_exploited AS k
              JOIN vulnerabilities AS v ON v.cve_id = k.cve_id
              WHERE v.assigner = f.assigner AND k.date_added <= f.snapshot_end
          )
    """
    assert con.execute(mismatches).fetchone()[0] == 0


# --- SHE-31 ---


def test_no_nist_sourced_cvss(con):
    leaked = f"""
        SELECT count(*) FROM {FEATURES} AS f
        JOIN vulnerabilities AS v ON v.cve_id = f.cve_id
        WHERE v.cvss3_source = 'nvd@nist.gov' AND f.cvss3_score IS NOT NULL
    """
    assert con.execute(leaked).fetchone()[0] == 0
    assert (
        con.execute(f"SELECT count(*) FROM {FEATURES} WHERE cwe_primary IS NULL").fetchone()[0] == 0
    )


# --- SHE-32 ---


def test_keywords_are_flags(con):
    columns = [r[0] for r in con.execute(f"DESCRIBE SELECT * FROM {FEATURES}").fetchall()]
    keywords = [c for c in columns if c.startswith("kw_")]
    assert len(keywords) == 11
    for column in keywords:
        assert con.execute(f"SELECT max({column}) FROM {FEATURES}").fetchone()[0] in (0, 1)


# --- SHE-33 ---


def test_no_banned_columns(log):
    assert log["banned_columns"] == 0
