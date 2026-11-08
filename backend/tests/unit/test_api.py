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
