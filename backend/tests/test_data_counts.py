"""SHE-17: the Parquet copies have exactly the rows the README lists.

Skipped when data/parquet/ hasn't been built (fresh clone, CI).
"""

import pytest

from backend.core.config import PARQUET_DIR
from backend.db.warehouse import connect

EXPECTED_ROWS = {
    "vulnerabilities": 401_082,
    "affected_products": 3_155_934,
    "references": 1_360_487,
    "known_exploited": 1_484,
    "exploit_signals_2024": 3_023_284,
    "exploit_signals_2025": 3_440_450,  # 2024 + 2025 = 6,463,734, as in the README
    "weakness_types": 1_374,
    "scoreboard_2026": 72_670,
}

pytestmark = pytest.mark.skipif(
    not (PARQUET_DIR / "vulnerabilities.parquet").exists(),
    reason="no Parquet data: run `uv run python -m backend.load` first",
)


@pytest.fixture(scope="module")
def con():
    return connect()


@pytest.mark.parametrize(("table", "expected"), EXPECTED_ROWS.items())
def test_row_count(con, table, expected):
    assert con.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0] == expected


def column_type(con, table: str, column: str) -> str:
    rows = con.execute(f'DESCRIBE "{table}"').fetchall()
    return {r[0]: r[1] for r in rows}[column]


def test_versions_are_text(con):
    for column in ("version", "version_end_excluding"):
        assert column_type(con, "affected_products", column) == "VARCHAR"


def test_typed_columns(con):
    assert column_type(con, "vulnerabilities", "published") == "DATE"
    assert column_type(con, "vulnerabilities", "cvss3_score") == "DOUBLE"
    assert column_type(con, "known_exploited", "date_added") == "DATE"
    assert column_type(con, "exploit_signals_2025", "epss") == "DOUBLE"


def test_cve_ids_unique(con):
    total, distinct = con.execute(
        "SELECT count(*), count(DISTINCT cve_id) FROM vulnerabilities"
    ).fetchone()
    assert total == distinct
