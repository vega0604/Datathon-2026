"""SHE-18 to SHE-22: clean the typed Parquet tables into data/clean/.

Run after `uv run python -m backend.load`:

    uv run python -m backend.clean

Each step is a function that returns SQL, so it can be unit-tested on tiny tables
(tests/test_clean.py) without the real data. main() runs the steps on the real
tables, writes data/clean/*.parquet, and records row counts in
outputs/logs/clean_log.json (checked by tests/test_clean_data.py).
"""

import json

import duckdb

from backend.paths import CLEAN_DIR, LOGS_DIR, PARQUET_DIR
from backend.warehouse import connect


def write_parquet(con: duckdb.DuckDBPyConnection, query: str, name: str) -> int:
    CLEAN_DIR.mkdir(parents=True, exist_ok=True)
    path = (CLEAN_DIR / f"{name}.parquet").as_posix()
    con.execute(f"COPY ({query}) TO '{path}' (FORMAT parquet, COMPRESSION zstd)")
    return con.execute(f"SELECT count(*) FROM read_parquet('{path}')").fetchone()[0]


def count(con: duckdb.DuckDBPyConnection, table: str) -> int:
    return con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


# --- SHE-18: weakness types, one row per CVE-CWE pair -------------------------

UNKNOWN_CWE = "unknown"
PLACEHOLDER_CWES = ("NVD-CWE-Other", "NVD-CWE-noinfo")


def cwe_long_sql(vulns: str = "vulnerabilities") -> str:
    """One row per (cve_id, cwe_id). Blank cwe_ids and NIST's placeholders become
    'unknown', so every CVE has at least one row."""
    placeholders = ", ".join(f"'{c}'" for c in PLACEHOLDER_CWES)
    return f"""
        SELECT DISTINCT
            cve_id,
            CASE WHEN cwe = '' OR cwe IN ({placeholders}) THEN '{UNKNOWN_CWE}' ELSE cwe END
                AS cwe_id
        FROM (
            SELECT cve_id, trim(cwe) AS cwe
            FROM (
                SELECT cve_id, unnest(string_split(coalesce(cwe_ids, ''), ';')) AS cwe
                FROM {vulns}
            )
        )
        ORDER BY cve_id, cwe_id
    """


def main() -> None:
    if not (PARQUET_DIR / "vulnerabilities.parquet").exists():
        raise SystemExit("No Parquet data. Run `uv run python -m backend.load` first.")
    con = connect()
    log: dict[str, int] = {}
    log["cwe"] = write_parquet(con, cwe_long_sql(), "cwe")
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "clean_log.json").write_text(json.dumps(log, indent=2) + "\n")
    for name, value in log.items():
        print(f"{name:<32} {value:>10,}")


if __name__ == "__main__":
    main()
