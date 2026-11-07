"""Checks on the real cleaned data in data/clean/ (SHE-18 to SHE-22).

Expected numbers were measured from the challenge data on 2026-11-07. Skipped
until `uv run python -m backend.clean` has run.
"""

import json

import pytest

from backend.paths import LOGS_DIR
from backend.warehouse import connect

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
