"""Storage for uploaded SBOMs: a separate DuckDB file attached to the warehouse as schema `app`."""

import duckdb

from backend.core import config
from backend.db import warehouse


def init_store(con: duckdb.DuckDBPyConnection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS app.sboms (
            sbom_id VARCHAR PRIMARY KEY,
            name VARCHAR,
            filename VARCHAR,
            uploaded_at TIMESTAMP,
            component_count INTEGER
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS app.components (
            sbom_id VARCHAR,
            component_id INTEGER,
            name VARCHAR,
            group_name VARCHAR,
            version VARCHAR,
            purl VARCHAR,
            cpe VARCHAR,
            vendor VARCHAR,
            product VARCHAR,
            PRIMARY KEY (sbom_id, component_id)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS app.matches (
            sbom_id VARCHAR,
            component_id INTEGER,
            cve_id VARCHAR,
            method VARCHAR,
            version_status VARCHAR,
            PRIMARY KEY (sbom_id, component_id, cve_id)
        )
        """
    )


def open_database(app_db: str | None = None) -> duckdb.DuckDBPyConnection:
    """Open the warehouse and attach the app store. `app_db=":memory:"` is for tests."""
    if config.DATA_BACKEND != "duckdb":
        raise NotImplementedError(f"DATA_BACKEND={config.DATA_BACKEND!r} (Tiger arrives in SHE-10)")
    con = warehouse.connect()
    path = app_db if app_db is not None else str(config.APP_DB_PATH)
    if path != ":memory:":
        config.APP_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con.execute(f"ATTACH '{path}' AS app")
    init_store(con)
    return con
