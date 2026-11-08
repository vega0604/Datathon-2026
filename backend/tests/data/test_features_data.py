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
