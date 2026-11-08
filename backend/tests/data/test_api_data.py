"""End-to-end check of the API on the real data and the demo SBOM (SHE-109)."""

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.core.config import CLEAN_DIR, DEMO_DIR
from backend.db.store import open_database
from backend.services.queue import predictions_source

pytestmark = pytest.mark.skipif(
    not (CLEAN_DIR / "affected_products.parquet").exists(),
    reason="no cleaned data: run the load and clean pipeline first",
)


@pytest.fixture(scope="module")
def con():
    con = open_database(":memory:")
    yield con
    con.close()


@pytest.fixture(scope="module")
def uploaded(con):
    path = DEMO_DIR / "acme_sbom.cdx.json"
    with TestClient(create_app(con)) as client:
        r = client.post("/api/sboms", files={"file": (path.name, path.read_bytes())})
        assert r.status_code == 201
        sbom_id = r.json()["sbom_id"]
        comps = client.get(f"/api/sboms/{sbom_id}/components").json()["components"]
    return sbom_id, {c["name"]: c for c in comps}


def test_matches_in_scoreboard_and_kev(con, uploaded):
    sbom_id, _ = uploaded
    total, in_board, on_kev = con.execute(
        """
        SELECT count(DISTINCT m.cve_id),
               count(DISTINCT m.cve_id) FILTER (WHERE s.cve_id IS NOT NULL),
               count(DISTINCT m.cve_id) FILTER (WHERE k.cve_id IS NOT NULL)
        FROM app.matches m
        LEFT JOIN scoreboard_2026 s ON s.cve_id = m.cve_id
        LEFT JOIN clean.kev k ON k.cve_id = m.cve_id
        WHERE m.sbom_id = ?
        """,
        [sbom_id],
    ).fetchone()
    assert in_board >= 30
    assert on_kev >= 10
    assert total >= in_board


def test_wordpress_has_fewer_matches_than_chrome(uploaded):
    _, comps = uploaded
    wordpress = comps["WordPress"]["risk"]["cve_count"]
    assert wordpress < comps["Google Chrome"]["risk"]["cve_count"]


def test_queue_kev_first_and_total(con, uploaded):
    sbom_id, _ = uploaded
    with TestClient(create_app(con)) as client:
        body = client.get(f"/api/sboms/{sbom_id}/queue?limit=20").json()
    distinct = con.execute(
        "SELECT count(DISTINCT cve_id) FROM app.matches WHERE sbom_id = ?", [sbom_id]
    ).fetchone()[0]
    assert body["ranking"] == ("model" if predictions_source() else "epss_placeholder")
    assert body["total"] == distinct
    assert len(body["items"]) == 20
    assert all(i["on_kev"] for i in body["items"])
