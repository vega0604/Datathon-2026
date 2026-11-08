import json

import pytest

from backend.services.queue import build_queue
from backend.services.sbom import parse_cyclonedx, store_sbom


def add_cve(db, cve, cvss=None, epss=None, month="2026-09", kev=False):
    db.execute(
        "INSERT INTO vulnerabilities VALUES (?, DATE '2026-01-01', ?, ?, NULL)",
        [cve, f"desc {cve}", cvss],
    )
    if epss is not None:
        db.execute(
            "INSERT INTO scoreboard_2026 VALUES (?, DATE '2026-01-01', ?, ?, 0, 0, 0, 0)",
            [cve, month, epss],
        )
    if kev:
        db.execute(
            "INSERT INTO clean.kev VALUES (?, 'v', 'p', 'n', DATE '2026-02-02', 'Known', 'v')",
            [cve],
        )


@pytest.fixture
def sid(db):
    bom = {"bomFormat": "CycloneDX", "components": [{"name": "zeta"}, {"name": "alpha"}]}
    _, comps = parse_cyclonedx(json.dumps(bom).encode())
    return store_sbom(db, "t", "t.json", comps)


def match(db, sid, cve, component_id=1, status="in_range"):
    db.execute(
        "INSERT INTO app.matches VALUES (?, ?, ?, 'cpe', ?)", [sid, component_id, cve, status]
    )


@pytest.fixture
def queue_sid(db, sid):
    add_cve(db, "A", cvss=5.0, epss=0.01, kev=True)  # KEV beats a higher score
    add_cve(db, "B", cvss=3.0, epss=0.9)
    add_cve(db, "C", cvss=9.0, epss=0.5)
    add_cve(db, "D", cvss=9.0, epss=0.5)  # ties with C on score and CVSS: id breaks it
    add_cve(db, "E", cvss=4.0, epss=0.5)  # same score as C, lower CVSS
    add_cve(db, "F", cvss=10.0)  # no signal at all: after every scored CVE
    for cve in "ABCDEF":
        match(db, sid, cve)
    return sid


def test_ordering(db, queue_sid):
    q = build_queue(db, queue_sid)
    assert [i["cve_id"] for i in q["items"]] == list("ABCDEF")
    assert [i["rank"] for i in q["items"]] == [1, 2, 3, 4, 5, 6]
    assert q["total"] == 6 and q["ranking"] == "epss_placeholder"
    a = q["items"][0]
    assert a["on_kev"] and a["known_ransomware"] and str(a["kev_date_added"]) == "2026-02-02"


def test_cvss_rank_is_independent(db, queue_sid):
    q = build_queue(db, queue_sid)
    by_id = {i["cve_id"]: i["cvss_rank"] for i in q["items"]}
    assert by_id == {"F": 1, "C": 2, "D": 3, "A": 4, "E": 5, "B": 6}


def test_paging_keeps_ranks(db, queue_sid):
    q = build_queue(db, queue_sid, limit=2, offset=2)
    assert [(i["rank"], i["cve_id"]) for i in q["items"]] == [(3, "C"), (4, "D")]
    assert q["total"] == 6
    past = build_queue(db, queue_sid, limit=2, offset=50)
    assert past["items"] == [] and past["total"] == 6


def test_scoreboard_beats_older_signals(db, sid):
    add_cve(db, "W", cvss=1.0, epss=0.3, month="2026-01")
    add_cve(db, "X", cvss=1.0)
    db.execute(
        "INSERT INTO clean.exploit_signals VALUES "
        "('2025-12', 'W', 0.99, 0.99, 0, 0, 0, 0), "
        "('2025-06', 'X', 0.10, 0.10, 0, 0, 0, 0), "
        "('2025-11', 'X', 0.20, 0.20, 0, 1, 0, 0)"
    )
    match(db, sid, "W")
    match(db, sid, "X")
    items = {i["cve_id"]: i for i in build_queue(db, sid)["items"]}
    assert items["W"]["epss"] == 0.3
    assert items["X"]["epss"] == 0.2 and items["X"]["score"] == 0.2  # latest month wins
    assert items["X"]["exploit_code"] is True and items["W"]["exploit_code"] is False


def test_components_sorted_distinct_and_status(db, sid):
    add_cve(db, "A", cvss=1.0)
    match(db, sid, "A", 1, "unverified")
    match(db, sid, "A", 2, "in_range")
    item = build_queue(db, sid)["items"][0]
    assert item["components"] == ["alpha", "zeta"]
    assert item["version_status"] == "in_range"


def test_queue_endpoint(client, db, sid):
    add_cve(db, "A", cvss=1.0)
    match(db, sid, "A", 1, "unverified")
    body = client.get(f"/api/sboms/{sid}/queue?limit=5").json()
    assert body["total"] == 1 and body["items"][0]["version_status"] == "unverified"
    assert body["items"][0]["reasons"] == [] and body["items"][0]["explanation"] is None
    assert client.get(f"/api/sboms/{sid}/queue?limit=0").status_code == 422
    assert client.get(f"/api/sboms/{sid}/queue?limit=1001").status_code == 422
    assert client.get("/api/sboms/nope/queue").status_code == 404
