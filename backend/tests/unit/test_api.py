from fastapi.testclient import TestClient

from backend.api.app import create_app


def test_health():
    with TestClient(create_app()) as client:
        r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_cors_allows_vite():
    with TestClient(create_app()) as client:
        r = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_meta(client):
    r = client.get("/api/meta")
    assert r.status_code == 200
    assert r.json() == {"data_backend": "duckdb", "vulnerabilities": 1}


def test_upload_demo_sbom(client):
    from backend.core.config import DEMO_DIR

    path = DEMO_DIR / "acme_sbom.cdx.json"
    r = client.post("/api/sboms", files={"file": (path.name, path.read_bytes())})
    assert r.status_code == 201
    body = r.json()
    assert body["component_count"] == 22 and len(body["components"]) == 22
    assert client.get(f"/api/sboms/{body['sbom_id']}").json()["name"] == "Acme Logistics Platform"
    assert [s["sbom_id"] for s in client.get("/api/sboms").json()] == [body["sbom_id"]]


def test_upload_garbage_is_422(client):
    r = client.post("/api/sboms", files={"file": ("x.json", b"garbage")})
    assert r.status_code == 422
    assert "JSON" in r.json()["detail"]


def test_unknown_sbom_is_404(client):
    assert client.get("/api/sboms/doesnotexist").status_code == 404


def test_components_endpoint_counts(client, db):
    import json

    for cve, vendor in [("CVE-A", "acme"), ("CVE-B", "acme"), ("CVE-C", "other")]:
        db.execute(
            "INSERT INTO clean.affected_products (cve_id, vendor, product, version, vulnerable, "
            "vendor_key) VALUES (?, ?, 'widget', '*', 'Y', ?)",
            [cve, vendor, vendor],
        )
    db.execute("INSERT INTO clean.kev (cve_id) VALUES ('CVE-A')")
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "w", "version": "1", "cpe": "cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*"},
            {"name": "nothing", "purl": "pkg:npm/nothing@1"},
        ],
    }
    r = client.post("/api/sboms", files={"file": ("b.json", json.dumps(bom).encode())})
    sid = r.json()["sbom_id"]
    body = client.get(f"/api/sboms/{sid}/components").json()
    counts = [(c["name"], c["matched_cves"], c["kev_cves"]) for c in body["components"]]
    assert counts == [("w", 2, 1), ("nothing", 0, 0)]
    assert client.get("/api/sboms/nope/components").status_code == 404
