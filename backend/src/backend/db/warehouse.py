"""One DuckDB connection over the project's Parquet files.

    con = connect()
    con.sql('SELECT count(*) FROM vulnerabilities')        # data/parquet/*.parquet
    con.sql('SELECT count(*) FROM clean.exploit_signals')  # data/clean/*.parquet

Every Parquet file becomes a view named after the file. Names are quoted because
"references" is a reserved word in SQL: write "references" in your queries.
"""

import duckdb

from backend.core.config import CLEAN_DIR, PARQUET_DIR


def connect(database: str = ":memory:") -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(database)
    for path in sorted(PARQUET_DIR.glob("*.parquet")):
        con.execute(
            f'CREATE OR REPLACE VIEW "{path.stem}" AS '
            f"SELECT * FROM read_parquet('{path.as_posix()}')"
        )
    con.execute("CREATE SCHEMA IF NOT EXISTS clean")
    for path in sorted(CLEAN_DIR.glob("*.parquet")):
        con.execute(
            f'CREATE OR REPLACE VIEW clean."{path.stem}" AS '
            f"SELECT * FROM read_parquet('{path.as_posix()}')"
        )
    return con
