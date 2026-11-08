"""SHE-16: convert the raw CSVs in data/raw/ to typed Parquet in data/parquet/.

Run: uv run python -m backend.pipeline.load

Every column is read as text first (so nothing is guessed wrong, and version
strings like "1.10" stay "1.10"), then the columns below are cast. Blank values
become NULL. A value that doesn't parse makes the load fail loudly instead of
silently turning into NULL.
"""

import duckdb

from backend.core.config import PARQUET_DIR, RAW_DIR

FLAGS = ("exploitdb", "metasploit", "nuclei", "poc_github")
SIGNAL_TYPES = {"epss": "DOUBLE", "in_kev": "UTINYINT"} | {f: "UTINYINT" for f in FLAGS}

# table name -> {column: type}. Columns not listed stay text (VARCHAR).
TABLES: dict[str, dict[str, str]] = {
    "vulnerabilities": {
        "published": "DATE",
        "last_modified": "DATE",
        "cvss3_score": "DOUBLE",
        "cvss3_exploitability_score": "DOUBLE",
        "cvss3_impact_score": "DOUBLE",
        "cvss4_score": "DOUBLE",
        "cvss2_score": "DOUBLE",
        "n_references": "INTEGER",
        "n_affected_cpes": "INTEGER",
    },
    "affected_products": {},  # all text, including the version columns
    "references": {},
    "known_exploited": {"date_added": "DATE", "due_date": "DATE"},
    "exploit_signals_2024": SIGNAL_TYPES,
    "exploit_signals_2025": SIGNAL_TYPES,
    "weakness_types": {},
    "scoreboard_2026": {"published": "DATE", "epss": "DOUBLE"} | {f: "UTINYINT" for f in FLAGS},
}


def select_sql(csv_path: str, types: dict[str, str]) -> str:
    source = (
        f"read_csv('{csv_path}', header = true, all_varchar = true, quote = '\"', escape = '\"')"
    )
    if not types:
        return f"SELECT * FROM {source}"
    casts = ", ".join(f'CAST(NULLIF(trim("{c}"), \'\') AS {t}) AS "{c}"' for c, t in types.items())
    return f"SELECT * REPLACE ({casts}) FROM {source}"


def convert(con: duckdb.DuckDBPyConnection, name: str) -> int:
    src = (RAW_DIR / f"{name}.csv").as_posix()
    dst = (PARQUET_DIR / f"{name}.parquet").as_posix()
    con.execute(
        f"COPY ({select_sql(src, TABLES[name])}) TO '{dst}' (FORMAT parquet, COMPRESSION zstd)"
    )
    return con.execute(f"SELECT count(*) FROM read_parquet('{dst}')").fetchone()[0]


def main() -> None:
    missing = [n for n in TABLES if not (RAW_DIR / f"{n}.csv").exists()]
    if missing:
        raise SystemExit(f"Missing in {RAW_DIR}: {', '.join(missing)}. Unzip data.zip there first.")
    PARQUET_DIR.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    for name in TABLES:
        print(f"{name:<22} {convert(con, name):>10,} rows")


if __name__ == "__main__":
    main()
