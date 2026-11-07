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


# --- SHE-19 to SHE-21: monthly exploit signals ---------------------------------


def signals_union_sql() -> str:
    return "SELECT * FROM exploit_signals_2024 UNION ALL SELECT * FROM exploit_signals_2025"


def drop_rejected_sql(src: str, vulns: str = "vulnerabilities") -> str:
    """SHE-19: drop rows whose ID isn't in vulnerabilities (rejected IDs)."""
    return f"SELECT * FROM {src} WHERE cve_id IN (SELECT cve_id FROM {vulns})"


def fill_feb_2025_sql(src: str) -> str:
    """SHE-20: February 2025 is missing ~14,500 CVEs. A CVE present in January and
    March but not February gets January's values for February, with filled_gap = 1."""
    return f"""
        SELECT *, 0::UTINYINT AS filled_gap FROM {src}
        UNION ALL
        SELECT * REPLACE ('2025-02' AS month), 1::UTINYINT AS filled_gap
        FROM {src}
        WHERE month = '2025-01'
          AND cve_id IN (SELECT cve_id FROM {src} WHERE month = '2025-03')
          AND cve_id NOT IN (SELECT cve_id FROM {src} WHERE month = '2025-02')
    """


def add_epss_pct_sql(src: str) -> str:
    """SHE-21: EPSS changed its model in March 2025, so raw scores aren't comparable
    across months. epss_pct ranks each score within its month (0 = lowest, 1 = highest).
    NULL where the CVE had no EPSS score that month."""
    return f"""
        SELECT
            *,
            CASE
                WHEN epss IS NULL THEN NULL
                ELSE percent_rank() OVER (PARTITION BY month, epss IS NULL ORDER BY epss)
            END AS epss_pct
        FROM {src}
    """


# Applied in order to the 2024 + 2025 signals. Each entry: (log name, step).
SIGNAL_STEPS = [
    ("drop_rejected", drop_rejected_sql),
    ("fill_feb_2025", fill_feb_2025_sql),
    ("epss_pct", add_epss_pct_sql),
]


def build_signals(con: duckdb.DuckDBPyConnection, log: dict[str, int]) -> int:
    con.execute(f"CREATE OR REPLACE TEMP TABLE signals AS {signals_union_sql()}")
    log["signals_raw"] = count(con, "signals")
    for name, step in SIGNAL_STEPS:
        con.execute(f"CREATE OR REPLACE TEMP TABLE signals_next AS {step('signals')}")
        con.execute("DROP TABLE signals")
        con.execute("ALTER TABLE signals_next RENAME TO signals")
        log[f"signals_after_{name}"] = count(con, "signals")
    return write_parquet(con, "SELECT * FROM signals ORDER BY month, cve_id", "exploit_signals")


def main() -> None:
    if not (PARQUET_DIR / "vulnerabilities.parquet").exists():
        raise SystemExit("No Parquet data. Run `uv run python -m backend.load` first.")
    con = connect()
    log: dict[str, int] = {}
    log["cwe"] = write_parquet(con, cwe_long_sql(), "cwe")
    log["exploit_signals"] = build_signals(con, log)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "clean_log.json").write_text(json.dumps(log, indent=2) + "\n")
    for name, value in log.items():
        print(f"{name:<32} {value:>10,}")


if __name__ == "__main__":
    main()
