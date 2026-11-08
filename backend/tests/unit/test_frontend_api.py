"""Unit tests for the frontend API handoff: queue rows, status, Linear, SBOM upload and
delete, components risk, insights, benchmark and /api/me. No network."""

import json

import numpy as np
import pandas as pd
import pytest

from backend.core import config
from backend.modeling import explain
from backend.services import granite_explain, linear
from backend.services import queue as q
from backend.services.components import cpe_part, newest
from backend.services.sbom import parse_sbom


def upload(client, bom, name="b.json"):
    return client.post("/api/sboms", files={"file": (name, json.dumps(bom).encode())})


@pytest.fixture
def sid(client, db):
    db.execute(
        "INSERT INTO clean.affected_products (cve_id, vendor, product, version, vulnerable, "
        "vendor_key) VALUES ('CVE-2025-0001', 'acme', 'widget', '*', 'Y', 'acme')"
    )
    db.execute(
        "INSERT INTO vulnerabilities (cve_id, published, description, cvss3_score, cwe_ids) "
        "VALUES ('CVE-2025-0001', DATE '2025-02-01', 'Acme Widget lets attackers write memory. "
        "More detail.', 9.8, 'CWE-787')"
    )
    db.execute(
        "INSERT INTO clean.kev VALUES ('CVE-2025-0001', 'Acme Corp', 'Widget', 'Acme Widget "
        "RCE', DATE '2025-03-01', 'Known', 'acme')"
    )
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"name": "Widget", "version": "1", "cpe": "cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*"}]}  # fmt: skip
    r = upload(client, bom)
    assert r.status_code == 201
    return r.json()["sbom_id"]


# --- queue rows -------------------------------------------------------------------------


def test_queue_row_fields(client, sid):
    body = client.get(f"/api/sboms/{sid}/queue").json()
    row = body["items"][0]
    assert row["component"] == "Widget"
    assert row["severity"] == "critical" and row["cvss_score"] == 9.8
    assert row["vendor_initials"] == "AC" and row["subtitle"] == "Acme Corp · Widget · 1 SBOM asset"
    assert row["explanation"] == (
        "Acme Widget lets attackers write memory. CISA confirms attackers are using it, "
        "including in ransomware."
    )
    assert row["explanation_source"] == "nvd"
    assert row["cwe_id"] == "CWE-787" and row["cwe_name"] == "Out-of-bounds Write"
    assert row["kev_name"] == "Acme Widget RCE" and "xforce" not in row
    assert body["counts"] == {"open": 1, "critical": 1, "not_in_linear": 1, "warning_signs": 0}
    assert body["matched"] == 1


def test_queue_search_filter_sort(client, sid):
    base = f"/api/sboms/{sid}/queue"
    assert client.get(f"{base}?q=widg").json()["matched"] == 1
    assert client.get(f"{base}?q=cve-2025-0001").json()["matched"] == 1
    none = client.get(f"{base}?q=nothing&view=critical").json()
    assert none["matched"] == 0 and none["items"] == [] and none["total"] == 1
    assert client.get(f"{base}?view=warning_signs").json()["matched"] == 0
    assert client.get(f"{base}?view=bogus").status_code == 422


def test_filter_rows():
    rows = [
        {"rank": 1, "cve_id": "CVE-1", "component": "A", "components": ["A"], "severity": "high",
         "cvss_score": 7.5, "ticket": None, "signal": "exploit_code"},
        {"rank": 2, "cve_id": "CVE-2", "component": "B", "components": ["B", "Zlib"],
         "severity": "critical", "cvss_score": 9.8, "ticket": {"id": "T"}, "signal": None},
        {"rank": 3, "cve_id": "CVE-3", "component": "C", "components": ["C"], "severity": "high",
         "cvss_score": 7.5, "ticket": None, "signal": None},
    ]  # fmt: skip
    ids = lambda out: [r["cve_id"] for r in out]
    assert ids(q.filter_rows(rows, q="zlib")) == ["CVE-2"]  # any matched component
    assert ids(q.filter_rows(rows, view="not_in_linear")) == ["CVE-1", "CVE-3"]
    assert ids(q.filter_rows(rows, view="warning_signs")) == ["CVE-1"]
    assert ids(q.filter_rows(rows, sort="cvss_desc")) == ["CVE-2", "CVE-1", "CVE-3"]
    assert ids(q.filter_rows(rows, sort="cvss_asc")) == ["CVE-1", "CVE-3", "CVE-2"]
    assert ids(rows) == ["CVE-1", "CVE-2", "CVE-3"]  # input untouched


def test_status_patch(client, sid):
    r = client.patch(f"/api/sboms/{sid}/queue/cve-2025-0001", json={"status": "in_progress"})
    assert r.status_code == 200 and r.json()["status"] == "in_progress"
    assert client.get(f"/api/sboms/{sid}/queue").json()["items"][0]["status"] == "in_progress"
    assert (
        client.patch(f"/api/sboms/{sid}/queue/CVE-2025-0001", json={"status": "x"}).status_code
        == 422
    )
    assert (
        client.patch(f"/api/sboms/{sid}/queue/CVE-1999-1", json={"status": "done"}).status_code
        == 404
    )
    assert (
        client.patch("/api/sboms/nope/queue/CVE-2025-0001", json={"status": "done"}).status_code
        == 404
    )


class FakeLinear:
    def __init__(self):
        self.calls = []

    def __call__(self, payload):
        self.calls.append(payload)
        data = (
            {"teams": {"nodes": [{"id": "team-1", "key": "SHE"}]}}
            if "teams" in payload["query"]
            else {"issueCreate": {"success": True, "issue": {"identifier": "SHE-123",
                                                             "url": "https://linear.app/x/SHE-123"}}}
        )  # fmt: skip

        class Response:
            def raise_for_status(self):
                pass

            def json(self):
                return {"data": data}

        return Response()


def test_push_to_linear_once(client, sid, monkeypatch):
    fake = FakeLinear()
    monkeypatch.setattr(config, "LINEAR_API_KEY", "key")
    monkeypatch.setattr(config, "LINEAR_TEAM_KEY", "SHE")
    real = linear.create_ticket
    monkeypatch.setattr(
        "backend.api.routes.sboms.create_ticket", lambda con, s, row: real(con, s, row, post=fake)
    )
    r = client.post(f"/api/sboms/{sid}/queue/CVE-2025-0001/linear")
    assert r.status_code == 201
    assert r.json() == {"ticket": {"id": "SHE-123", "url": "https://linear.app/x/SHE-123"}}
    created = fake.calls[1]["variables"]["input"]
    assert created["title"] == "CVE-2025-0001 · Widget" and "nvd.nist.gov" in created["description"]
    again = client.post(f"/api/sboms/{sid}/queue/CVE-2025-0001/linear")
    assert again.status_code == 200 and len(fake.calls) == 2  # no second issue
    body = client.get(f"/api/sboms/{sid}/queue").json()
    assert body["items"][0]["ticket"]["id"] == "SHE-123" and body["counts"]["not_in_linear"] == 0


def test_linear_not_set_up_is_502(client, sid, monkeypatch):
    monkeypatch.setattr(config, "LINEAR_API_KEY", "")
    r = client.post(f"/api/sboms/{sid}/queue/CVE-2025-0001/linear")
    assert r.status_code == 502 and "isn't set up" in r.json()["detail"]


# --- SBOMs ----------------------------------------------------------------------------------


def test_upload_returns_components_with_risk(client, sid):
    body = client.get(f"/api/sboms/{sid}/components").json()
    assert body["spec_version"] == "1.5" and body["risk_checked"]
    comp = body["components"][0]
    assert comp["vendor"] == "Acme Corp" and comp["part"] == "application"
    assert comp["risk"]["cve_count"] == 1 and comp["risk"]["severity"]["critical"] == 1
    assert comp["risk"]["kev"][0]["name"] == "Acme Widget RCE"
    assert comp["risk"]["top"][0]["kev"]["ransomware"] is True
    assert comp["match_methods"] == ["cpe"] and body["cve_total"] == 1
    assert body["uploaded_at"].endswith("Z")  # UTC, so browsers show local time


def test_reupload_replaces_and_delete(client, sid, db):
    client.patch(f"/api/sboms/{sid}/queue/CVE-2025-0001", json={"status": "done"})
    bom = {"bomFormat": "CycloneDX", "components": [{"name": "Widget"}]}
    new = upload(client, bom).json()["sbom_id"]  # same filename b.json
    assert [s["sbom_id"] for s in client.get("/api/sboms").json()] == [new]
    assert db.execute("SELECT count(*) FROM app.queue_status").fetchone()[0] == 0
    assert client.delete(f"/api/sboms/{new}").status_code == 204
    assert client.get("/api/sboms").json() == []
    assert client.delete(f"/api/sboms/{new}").status_code == 404


def test_xml_and_size_limits(client, monkeypatch):
    xml = b"""<?xml version="1.0"?>
    <bom xmlns="http://cyclonedx.org/schema/bom/1.4"><metadata><component type="application">
    <name>Shop</name></component></metadata><components><component type="library">
    <name>openssl</name><version>3.0.7</version><purl>pkg:generic/openssl@3.0.7</purl>
    <components><component><name>zlib</name></component></components></component></components>
    </bom>"""
    name, comps, spec = parse_sbom(xml)
    assert (name, spec, [c["name"] for c in comps]) == ("Shop", "1.4", ["openssl", "zlib"])
    assert comps[0]["version"] == "3.0.7"
    r = client.post("/api/sboms", files={"file": ("s.cdx.xml", xml)})
    assert r.status_code == 201 and r.json()["name"] == "Shop"
    monkeypatch.setattr("backend.services.sbom.MAX_BYTES", 10)
    monkeypatch.setattr("backend.api.routes.sboms.MAX_BYTES", 10)
    big = client.post("/api/sboms", files={"file": ("big.json", b"{" + b" " * 50 + b"}")})
    assert big.status_code == 413 and big.json()["detail"] == "That file is over 0 MB."


# --- insights, benchmark, me --------------------------------------------------------------


def test_insights_routes(client, tmp_path, monkeypatch):
    path = tmp_path / "insights.json"
    monkeypatch.setattr(config, "INSIGHTS_PATH", path)
    assert client.get("/api/insights/summary").status_code == 503
    data = {"summary": {"coverage": {"top_n": 500}}, "catch_rate": {"curves": []},
            "vendors": {"cells": []}, "benchmark": {"top_n": 500, "top_n_ready": True}}  # fmt: skip
    path.write_text(json.dumps(data), encoding="utf-8")
    assert client.get("/api/insights/summary").json() == {"coverage": {"top_n": 500}}
    assert client.get("/api/insights/catch-rate").json() == {"curves": []}
    assert client.get("/api/insights/vendors").json() == {"cells": []}
    monkeypatch.setattr(config, "OUTPUTS_DIR", tmp_path)  # no top500.csv here
    assert client.get("/api/benchmark").json()["top_n_ready"] is False


def test_insights_built_on_start_when_missing(tmp_path, monkeypatch):
    from backend.api.routes import insights as route

    path = tmp_path / "insights.json"
    monkeypatch.setattr(config, "INSIGHTS_PATH", path)
    monkeypatch.setattr(route, "_build", {"thread": None, "error": None})
    started = []
    monkeypatch.setattr(
        route, "_run_build", lambda: (started.append(1), path.write_text('{"summary": {}}'))
    )
    route.build_if_missing()
    route._build["thread"].join(5)
    assert started == [1] and route._insights() == {"summary": {}}
    route.build_if_missing()  # already there: no second build
    assert started == [1]


def test_cluster_labels_are_unique():
    from backend.modeling.insights import cluster_labels

    members = [["CWE-79"] * 5 + ["CWE-89"] * 2, ["CWE-79"] * 3 + ["CWE-22"], ["unknown"], []]
    assert cluster_labels(members) == ["CWE-79", "CWE-22", None, None]


def test_me(client, monkeypatch):
    monkeypatch.setattr(config, "ME_NAME", "Ada")
    assert client.get("/api/me").json() == {"name": "Ada", "role": config.ME_ROLE,
                                            "avatar_url": config.ME_AVATAR_URL}  # fmt: skip


# --- helpers ---------------------------------------------------------------------------------


def test_presentation_helpers():
    assert [q.severity(x) for x in (None, 0, 2.0, 5.0, 7.5, 9.0)] == [
        "none", "none", "low", "medium", "high", "critical",
    ]  # fmt: skip
    assert q.initials("WatchGuard") == "WG" and q.initials("Palo Alto Networks") == "PA"
    assert q.initials("apache") == "AP"
    assert q.display_vendor("paloaltonetworks", {"paloaltonetworks": "Palo Alto Networks"}) == (
        "Palo Alto Networks"
    )
    assert q.display_vendor("red_hat", {}) == "Red Hat"
    long = "word " * 100
    text = q.plain_explanation({"description": long, "on_kev": False, "exploit_code": True})
    assert len(text) < 200 and text.endswith(
        "Public attack code exists, but no confirmed attacks yet."
    )
    assert cpe_part("cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*") == "operating system"
    assert cpe_part("cpe:/h:cisco:router") == "hardware" and cpe_part(None) is None
    assert newest(["1.2.10", "1.2.9", "1.10"]) == "1.10"


def test_reason_bars():
    row = {"metasploit": 1, "nuclei": 0, "exploitdb": 0, "poc_github": 1, "epss_pct": 0.973,
           "assigner": "psirt@fortinet.com", "assigner_kev_prior": 2, "kev_sim_max": 0.9,
           "cvss3_score": 9.8, "attack_vector": "NETWORK", "privileges_required": "NONE",
           "cwe_primary": "unknown"}  # fmt: skip
    names = ["metasploit", "epss_pct", "assigner_kev_prior", "kev_sim_max", "cvss3_score"]
    contrib = np.array([[0.31, -0.2, 0.12, 0.05, -0.01]])
    bars = explain.bars_from_contributions(contrib, names, pd.DataFrame([row]))[0]
    assert bars == [
        {"kind": "exploit", "label": "Public exploit code (Metasploit, GitHub PoC)", "value": 0.31},
        {"kind": "vendor", "label": "Fortinet: 2 earlier KEV entries", "value": 0.12},
        {"kind": "exposure", "label": "Resembles exploited CVEs (0.90)", "value": 0.05},
    ]
    assert all(len(b["label"]) <= 45 for b in bars)
    assert explain.organisation("416baaa9-dc9f-4396-8d5f-8c081fb06d67") == "Its vendor"
    assert (
        explain.organisation(
            "psirt@paloaltonetworks.com", {"paloaltonetworks": "Palo Alto Networks"}
        )
        == "Palo Alto Networks"
    )
    four = ["Metasploit", "Nuclei", "Exploit-DB", "GitHub PoC"]
    assert explain.exploit_label(four) == "Public exploit code (Metasploit +3 more)"
    assert explain.short_cwe("Improper Control of Generation of Code ('Code Injection')") == (
        "Code Injection"
    )
    assert explain.short_label("exploit", {"metasploit": 0}) == "No public exploit code yet"


def test_granite_explanations_are_cached(db):
    class Client:
        calls = 0

        def chat(self, messages, max_tokens, temperature=0):
            Client.calls += 1
            return "**An attacker** can take over the device. Attacks are confirmed.", {}

    rows = [{"cve_id": "CVE-X", "component": "Widget", "description": "d", "on_kev": True,
             "explanation": "template", "explanation_source": "nvd"}]  # fmt: skip
    assert granite_explain.ensure_explanations(db, rows, client=Client()) == 1
    assert rows[0]["explanation"] == "An attacker can take over the device. Attacks are confirmed."
    assert rows[0]["explanation_source"] == "granite"
    stored = db.execute("SELECT text FROM app.explanations WHERE cve_id = 'CVE-X'").fetchone()
    assert stored[0] == rows[0]["explanation"]
    assert granite_explain.ensure_explanations(db, rows, client=Client()) == 0  # cached
    assert Client.calls == 1
