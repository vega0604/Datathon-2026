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
    # Older app.duckdb files predate spec_version.
    con.execute("ALTER TABLE app.sboms ADD COLUMN IF NOT EXISTS spec_version VARCHAR")
    # Queue status per SBOM and CVE (to_do / in_progress / done); missing = to_do.
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS app.queue_status (
            sbom_id VARCHAR,
            cve_id VARCHAR,
            status VARCHAR,
            updated_at TIMESTAMP,
            PRIMARY KEY (sbom_id, cve_id)
        )
        """
    )
    # Linear issues created from the queue.
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS app.tickets (
            sbom_id VARCHAR,
            cve_id VARCHAR,
            ticket_id VARCHAR,
            url VARCHAR,
            created_at TIMESTAMP,
            PRIMARY KEY (sbom_id, cve_id)
        )
        """
    )
    # Granite-written explanations, cached per CVE (each costs tokens once).
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS app.explanations (
            cve_id VARCHAR PRIMARY KEY,
            text VARCHAR,
            created_at TIMESTAMP
        )
        """
    )
    # Granite's verdict on description-only matches (optional, GRANITE_MATCH_CHECK).
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS app.match_checks (
            sbom_id VARCHAR,
            component_id INTEGER,
            cve_id VARCHAR,
            affected VARCHAR,
            confidence VARCHAR,
            reason VARCHAR,
            error BOOLEAN,
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
    try:
        con.execute(f"ATTACH '{path}' AS app")
    except duckdb.IOException as e:
        con.close()
        # DuckDB lets one process write a database file at a time: usually another API
        # server, a notebook kernel or pytest still has it open.
        raise RuntimeError(
            f"{path} is open in another process (another `uv run dev`, a notebook kernel "
            "or pytest). Stop that process, then start the server again."
        ) from e
    init_store(con)
    return con
