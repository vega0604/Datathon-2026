"""Checks on the real population (SHE-24 to SHE-26). Expected numbers were measured from
the challenge data on 2026-11-07. Skipped until the population has been built."""

import json

import pytest

from backend.core.config import FEATURES_DIR, LOGS_DIR
from backend.db.warehouse import connect
from backend.pipeline import population

LOG_PATH = LOGS_DIR / "population_log.json"
POPULATION = f"read_parquet('{(FEATURES_DIR / 'population.parquet').as_posix()}')"

pytestmark = pytest.mark.skipif(
    not LOG_PATH.exists(),
    reason="no population: run `uv run python -m backend.pipeline.population` first",
)


@pytest.fixture(scope="module")
def con():
    return connect()


@pytest.fixture(scope="module")
def log():
    return json.loads(LOG_PATH.read_text())


# --- SHE-24 ---


def test_candidates(log):
    assert log["candidates"] == 136_938  # 28,902 (2024) + 35,366 (2025) + 72,670 (2026)


def test_snapshot_rule_reproduces_the_scoreboard(con):
    rule = population.snapshot_month_sql("published")
    mismatches = f"SELECT count(*) FROM scoreboard_2026 WHERE {rule} <> snapshot_month"
    assert con.execute(mismatches).fetchone()[0] == 0
