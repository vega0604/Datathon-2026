import duckdb
import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.core import config
from backend.db.store import init_store


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch, tmp_path):
    """Unit tests never read the real predictions or call FIRST / watsonx unless they ask."""
    monkeypatch.setattr(config, "PREDICTIONS_PATH", tmp_path / "no_predictions.parquet")
    monkeypatch.setattr(config, "EPSS_LIVE", False)
    monkeypatch.setattr(config, "GRANITE_MATCH_CHECK", False)


@pytest.fixture
def db():
    """In-memory DuckDB with tiny tables named like the real warehouse views."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA clean")
    con.execute(
        """
        CREATE TABLE vulnerabilities (
            cve_id VARCHAR, published DATE, description VARCHAR,
            cvss3_score DOUBLE, cvss4_score DOUBLE, cwe_ids VARCHAR
        )
        """
    )
    con.execute("CREATE TABLE weakness_types (cwe_id VARCHAR, name VARCHAR)")
    con.execute("INSERT INTO weakness_types VALUES ('CWE-787', 'Out-of-bounds Write')")
    con.execute(
        """
        CREATE TABLE scoreboard_2026 (
            cve_id VARCHAR, published DATE, snapshot_month VARCHAR, epss DOUBLE,
            exploitdb UTINYINT, metasploit UTINYINT, nuclei UTINYINT, poc_github UTINYINT
        )
        """
    )
    con.execute(
        """
        CREATE TABLE clean.affected_products (
            cve_id VARCHAR, type VARCHAR, vendor VARCHAR, product VARCHAR, version VARCHAR,
            "update" VARCHAR, version_start_including VARCHAR, version_start_excluding VARCHAR,
            version_end_including VARCHAR, version_end_excluding VARCHAR, vulnerable VARCHAR,
            vendor_key VARCHAR
        )
        """
    )
    con.execute(
        "CREATE TABLE clean.vendor_aliases (kev_vendor VARCHAR, cpe_vendor VARCHAR, "
        "cves BIGINT, kev_cves BIGINT)"
    )
    con.execute(
        """
        CREATE TABLE clean.kev (
            cve_id VARCHAR, vendor VARCHAR, product VARCHAR, name VARCHAR, date_added DATE,
            known_ransomware_use VARCHAR, vendor_key VARCHAR
        )
        """
    )
    con.execute(
        """
        CREATE TABLE clean.exploit_signals (
            month VARCHAR, cve_id VARCHAR, epss DOUBLE, epss_pct DOUBLE,
            exploitdb UTINYINT, metasploit UTINYINT, nuclei UTINYINT, poc_github UTINYINT
        )
        """
    )
    con.execute(
        "INSERT INTO vulnerabilities (cve_id, published, description, cvss3_score) "
        "VALUES ('CVE-1', DATE '2024-01-01', 'd', 7.5)"
    )
    con.execute("ATTACH ':memory:' AS app")
    init_store(con)
    yield con
    con.close()


@pytest.fixture
def client(db):
    with TestClient(create_app(db)) as client:
        yield client
