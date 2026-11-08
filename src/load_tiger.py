"""
SHE-75: Tiger Data Bulk Loader.
Streams cleaned data from Parquet files into Tiger Data (Timescale Cloud)
using PostgreSQL COPY ... FROM STDIN via psycopg cursor.copy() for maximum throughput.
"""
import argparse
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import duckdb
from src.db import get_connection

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("load_tiger")

# Free tier storage limit: 750 MB
MAX_STORAGE_BYTES = 750 * 1024 * 1024

# Mapping of database tables to target columns and possible parquet filenames
TABLE_CONFIGS: Dict[str, Dict[str, Any]] = {
    "vulnerabilities": {
        "columns": ["cve_id", "published", "cwe_ids", "description"],
        "filenames": ["vulnerabilities.parquet", "cves.parquet"],
        "pk": ["cve_id"],
    },
    "known_exploited": {
        "columns": ["cve_id", "vendor", "product", "date_added", "short_description"],
        "filenames": ["known_exploited.parquet", "kev.parquet"],
        "pk": ["cve_id"],
    },
    "scoreboard": {
        "columns": [
            "cve_id",
            "published",
            "snapshot_month",
            "epss",
            "exploitdb",
            "metasploit",
            "nuclei",
            "poc_github",
        ],
        "filenames": ["scoreboard.parquet", "scoreboard_2026.parquet"],
        "pk": ["cve_id"],
    },
    "exploit_signals": {
        "columns": [
            "snapshot_month",
            "cve_id",
            "epss",
            "epss_pct",
            "in_kev",
            "exploitdb",
            "metasploit",
            "nuclei",
            "poc_github",
        ],
        "filenames": ["exploit_signals.parquet", "signals.parquet"],
        "pk": ["cve_id", "snapshot_month"],
    },
}


def find_parquet_file(data_dir: Path, filenames: List[str]) -> Optional[Path]:
    """Finds an existing Parquet file from a list of candidate filenames."""
    for name in filenames:
        candidate = data_dir / name
        if candidate.exists() and candidate.is_file():
            return candidate
        # Check subdirectories if partitioned
        candidate_dir = data_dir / name.replace(".parquet", "")
        if candidate_dir.exists() and candidate_dir.is_dir():
            return candidate_dir
    return None


def get_database_storage_bytes() -> Tuple[int, str]:
    """Returns the current database size in bytes and human-readable string."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_database_size(current_database()), pg_size_pretty(pg_database_size(current_database()));")
            size_bytes, size_pretty = cur.fetchone()
            return size_bytes, size_pretty


def load_table(
    table_name: str,
    parquet_path: Path,
    batch_size: int = 50000,
) -> int:
    """
    Streams records from Parquet into PostgreSQL using COPY ... FROM STDIN.
    Validates row counts and ensures memory efficiency.
    """
    config = TABLE_CONFIGS[table_name]
    target_columns = config["columns"]
    col_str = ", ".join(target_columns)

    logger.info(f"[*] Processing table '{table_name}' from {parquet_path.name}...")

    # Connect to DuckDB in-memory reader
    duck_conn = duckdb.connect()

    # Inspect Parquet schema to match column names case-insensitively
    parquet_cols_info = duck_conn.execute(f"DESCRIBE SELECT * FROM '{parquet_path.as_posix()}'").fetchall()
    parquet_col_names = {row[0].lower(): row[0] for row in parquet_cols_info}

    # Build SELECT query matching available columns
    select_expressions = []
    for col in target_columns:
        if col.lower() in parquet_col_names:
            select_expressions.append(f'"{parquet_col_names[col.lower()]}" AS "{col}"')
        elif col == "in_kev" and "in_kev" not in parquet_col_names:
            select_expressions.append("0 AS in_kev")
        else:
            select_expressions.append(f'NULL AS "{col}"')

    select_sql = f"SELECT {', '.join(select_expressions)} FROM '{parquet_path.as_posix()}'"
    
    # Get total row count from Parquet
    total_parquet_rows = duck_conn.execute(f"SELECT COUNT(*) FROM ({select_sql})").fetchone()[0]
    logger.info(f"[*] Source Parquet contains {total_parquet_rows:,} rows.")

    if total_parquet_rows == 0:
        logger.warning(f"[!] No rows to load for {table_name}.")
        return 0

    # Stream query result in batches
    duck_result = duck_conn.execute(select_sql)

    # Perform PostgreSQL COPY via psycopg
    copy_sql = f"COPY {table_name} ({col_str}) FROM STDIN"
    start_time = time.perf_counter()
    rows_streamed = 0

    with get_connection() as pg_conn:
        with pg_conn.cursor() as cur:
            # Check current row count
            cur.execute(f"SELECT COUNT(*) FROM {table_name}")
            initial_count = cur.fetchone()[0]

            if initial_count >= total_parquet_rows:
                logger.info(f"[+] Table '{table_name}' already populated ({initial_count:,} rows). Skipping COPY.")
                return initial_count

            logger.info(f"[*] Executing PostgreSQL COPY for {table_name}...")
            with cur.copy(copy_sql) as copy:
                while True:
                    batch = duck_result.fetchmany(batch_size)
                    if not batch:
                        break
                    for row in batch:
                        copy.write_row(row)
                    rows_streamed += len(batch)
                    logger.info(f"    Streamed {rows_streamed:,} / {total_parquet_rows:,} rows...")

        pg_conn.commit()

    duration = time.perf_counter() - start_time
    rate = rows_streamed / duration if duration > 0 else 0
    logger.info(f"[+] COPY completed for '{table_name}': {rows_streamed:,} rows in {duration:.2f}s ({rate:,.0f} rows/s).")

    # Assert and validate loaded count
    with get_connection() as pg_conn:
        with pg_conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {table_name}")
            final_count = cur.fetchone()[0]

    logger.info(f"[*] Verification: Parquet source = {total_parquet_rows:,} | DB destination = {final_count:,}")
    assert final_count >= total_parquet_rows, f"Row count mismatch on {table_name}: DB={final_count} < Parquet={total_parquet_rows}"

    return final_count


def run_bulk_loader(data_dir: Path, tables: Optional[List[str]] = None) -> Dict[str, int]:
    """Runs the bulk loader for all configured tables or a specified subset."""
    tables_to_load = tables or list(TABLE_CONFIGS.keys())
    results = {}

    initial_bytes, initial_pretty = get_database_storage_bytes()
    logger.info(f"[*] Initial Tiger Data storage footprint: {initial_pretty} ({initial_bytes:,} bytes).")

    for table in tables_to_load:
        if table not in TABLE_CONFIGS:
            logger.warning(f"[!] Unknown table '{table}'. Skipping.")
            continue

        parquet_file = find_parquet_file(data_dir, TABLE_CONFIGS[table]["filenames"])
        if not parquet_file:
            logger.warning(f"[!] No Parquet file found for table '{table}' in {data_dir}. Expected one of {TABLE_CONFIGS[table]['filenames']}.")
            continue

        loaded_count = load_table(table, parquet_file)
        results[table] = loaded_count

    final_bytes, final_pretty = get_database_storage_bytes()
    logger.info(f"[*] Final Tiger Data storage footprint: {final_pretty} ({final_bytes:,} bytes).")

    if final_bytes > MAX_STORAGE_BYTES:
        logger.error(f"[DANGER] Storage footprint ({final_pretty}) exceeds 750 MB free-tier budget!")
    else:
        margin_mb = (MAX_STORAGE_BYTES - final_bytes) / (1024 * 1024)
        logger.info(f"[+] Storage check PASSED: {margin_mb:.1f} MB remaining under the 750 MB ceiling.")

    return results


def main():
    parser = argparse.ArgumentParser(description="Tiger Data Parquet Bulk Loader via PostgreSQL COPY")
    parser.add_argument("--data-dir", type=str, default="data/parquet", help="Path to cleaned Parquet datasets directory")
    parser.add_argument("--tables", nargs="*", default=None, help="Specific tables to load (default: all)")
    args = parser.parse_args()

    data_path = (PROJECT_ROOT / args.data_dir).resolve()
    if not data_path.exists():
        logger.warning(f"[!] Data directory does not exist: {data_path}. Creating directory...")
        data_path.mkdir(parents=True, exist_ok=True)

    print(f"=== Tiger Data Bulk Loader (Story SHE-75) ===")
    print(f"Data Source Directory: {data_path}")
    results = run_bulk_loader(data_path, args.tables)
    print(f"[SUCCESS] Bulk loader finished. Summary: {results}")


if __name__ == "__main__":
    main()
