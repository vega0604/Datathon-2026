"""SHE-24 to SHE-26: who is in each backtest fold, when we look, and what happened.

Run after `uv run python -m backend.pipeline.clean`:

    uv run python -m backend.pipeline.population

Writes data/features/population.parquet: one row per vulnerability per fold.
Folds 2024 and 2025 rebuild the benchmark's rules in the past; fold 2026 is the
benchmark itself (scoreboard_2026).
"""

import json

import duckdb

from backend.core.config import FEATURES_DIR, LOGS_DIR, PARQUET_DIR
from backend.db.warehouse import connect

# Fold year -> last day a KEV addition counts (the benchmark's Nov 4, shifted back).
HISTORY_FOLDS = {2024: "2024-11-04", 2025: "2025-11-04"}
BENCHMARK_FOLD = 2026
BENCHMARK_CUTOFF = "2026-11-04"
# Months with no signal data: vulnerabilities published then use the next month.
MISSING_SIGNAL_MONTHS = {"2026-06": "2026-07"}


def write_parquet(con: duckdb.DuckDBPyConnection, query: str, name: str) -> int:
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
    path = (FEATURES_DIR / f"{name}.parquet").as_posix()
    con.execute(f"COPY ({query}) TO '{path}' (FORMAT parquet, COMPRESSION zstd)")
    return con.execute(f"SELECT count(*) FROM read_parquet('{path}')").fetchone()[0]


def count(con: duckdb.DuckDBPyConnection, table: str) -> int:
    return con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


# --- SHE-24: candidates and their snapshot month --------------------------------


def snapshot_month_sql(published: str) -> str:
    """The month whose data a vulnerability is scored with: its publish month,
    moved to the next month when signals for that month are missing."""
    month = f"strftime({published}, '%Y-%m')"
    shifts = " ".join(f"WHEN {month} = '{m}' THEN '{n}'" for m, n in MISSING_SIGNAL_MONTHS.items())
    return f"CASE {shifts} ELSE {month} END"


def candidates_sql(vulns: str = "vulnerabilities", scoreboard: str = "scoreboard_2026") -> str:
    """Every vulnerability published Jan-Sep of a history fold year, plus the scoreboard,
    with its snapshot month, the last day of that month, and its fold's label cutoff."""
    history = " UNION ALL ".join(
        f"""
        SELECT cve_id, {year} AS fold, published,
               {snapshot_month_sql("published")} AS snapshot_month, DATE '{cutoff}' AS cutoff
        FROM {vulns}
        WHERE published >= DATE '{year}-01-01' AND published < DATE '{year}-10-01'
        """
        for year, cutoff in HISTORY_FOLDS.items()
    )
    return f"""
        SELECT *, last_day(CAST(snapshot_month || '-01' AS DATE)) AS snapshot_end
        FROM (
            {history}
            UNION ALL
            SELECT cve_id, {BENCHMARK_FOLD} AS fold, published, snapshot_month,
                   DATE '{BENCHMARK_CUTOFF}' AS cutoff
            FROM {scoreboard}
        )
    """


# Applied in order to the candidates. Each entry: (log name, step).
POPULATION_STEPS: list = []


def build_population(con: duckdb.DuckDBPyConnection, log: dict[str, int]) -> int:
    con.execute(f"CREATE OR REPLACE TEMP TABLE population AS {candidates_sql()}")
    log["candidates"] = count(con, "population")
    for name, step in POPULATION_STEPS:
        con.execute(f"CREATE OR REPLACE TEMP TABLE population_next AS {step('population')}")
        con.execute("DROP TABLE population")
        con.execute("ALTER TABLE population_next RENAME TO population")
        log[f"after_{name}"] = count(con, "population")
    by_fold = "SELECT fold, count(*) FROM population GROUP BY fold ORDER BY fold"
    for fold, rows in con.execute(by_fold).fetchall():
        log[f"rows_{fold}"] = rows
    columns = [row[0] for row in con.execute("DESCRIBE population").fetchall()]
    if "label" in columns:
        positives = "SELECT fold, sum(label) FROM population WHERE label IS NOT NULL GROUP BY fold"
        for fold, total in con.execute(positives).fetchall():
            log[f"positives_{fold}"] = int(total)
    return write_parquet(con, "SELECT * FROM population ORDER BY fold, cve_id", "population")


def main() -> None:
    if not (PARQUET_DIR / "vulnerabilities.parquet").exists():
        raise SystemExit("No Parquet data. Run `uv run python -m backend.pipeline.load` first.")
    con = connect()
    log: dict[str, int] = {}
    log["population"] = build_population(con, log)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "population_log.json").write_text(json.dumps(log, indent=2) + "\n")
    for name, value in log.items():
        print(f"{name:<32} {value:>10,}")


if __name__ == "__main__":
    main()
