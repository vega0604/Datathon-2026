"""Unit tests for the model-ranked SBOM queue: description matching, Granite checks, the
predictions-based ranking, staleness and live EPSS. No network."""

import json
from datetime import date

import pandas as pd
import pytest

from backend.core import config
from backend.services import description_match as dm
from backend.services import epss_live
from backend.services.match_verify import verify_description_matches
from backend.services.queue import build_queue, month_end
from backend.services.sbom import parse_cyclonedx, store_sbom


def sbom(db, components):
    bom = {"bomFormat": "CycloneDX", "components": components}
    _, comps = parse_cyclonedx(json.dumps(bom).encode())
    return store_sbom(db, "t", "t.json", comps)


def add_vuln(db, cve, description, cvss=None):
    db.execute(
        "INSERT INTO vulnerabilities (cve_id, published, description, cvss3_score) "
        "VALUES (?, DATE '2026-03-01', ?, ?)",
        [cve, description, cvss],
    )


# --- description matching ---------------------------------------------------------------


def test_rule():
    assert dm.accept("fastjson", None, "a flaw in alibaba fastjson 1 2 allows rce")
    assert not dm.accept("fastjson", None, "a flaw in fastjsonx allows rce")  # whole words only
    assert not dm.accept("nginx", "f5", "nginx proxy manager by someone allows xss")  # vendor
    assert dm.accept("nginx", "f5", "f5 nginx plus allows request smuggling")
    assert dm.accept("keycloakx", "acme", "keycloakx (8 chars) is distinctive")
    assert not dm.usable("core") and not dm.usable("ssh") and dm.usable("openssl")
    # add-on hosts are not the vulnerable product
    assert not dm.accept("wordpress", None, "the webmention plugin for wordpress is vulnerable")
    assert not dm.accept("wordpress", None, "a wordpress plugin before 2 0 allows xss")
    assert not dm.accept("jenkins", None, "the foo plugin for the jenkins server is vulnerable")
    assert dm.accept("wordpress", None, "wordpress core before 6 4 allows xss")
    assert not dm.accept(
        "wordpress", None, "the foo plugin for wordpress allows xss in wordpress 6 4 admin"
    )  # about a plugin
    assert not dm.accept("mongodb", None, "langchain mongodb provides integrations for mongodb")
    late = "parse server before 8 6 contains a missing authorization check on its mongodb store"
    assert not dm.accept("mongodb", None, late)  # named after the first 12 words
    assert dm.accept("http server", "apache", "apache http server mod proxy module allows ssrf")
    assert not dm.accept("http server", "apache", "a bug in micrium os network http server")
    assert not dm.accept("wordpress", None, "sql injection in mappress maps for wordpress 2 9")
    assert not dm.accept("mongodb", None, "the mongodb c# driver bson code has a dos flaw")
    assert dm.accept("fortios", "fortinet", "fortinet fortios through 7.6.6 allows attackers")
    assert not dm.accept("django", None, "a vulnerability in django-haystack up to 3.3.0")
    assert not dm.accept("openssl", None, "openssl_encrypt versions before 1.4.9 leak files")
    assert not dm.accept("mongodb", None, "denial of service in reporting/mongodb.py in capev2")
    assert dm.accept("openssl", None, "an application using openssl. this flaw allows a crash")
    assert dm.normalise("Log4j-Core") == "log4j-core"
    assert dm.normalise("http_server") == "http server"
    head12 = "a flaw in the bson handling library of the mongodb c# driver allows a crash"
    assert not dm.accept("mongodb", None, head12)  # the driver context is past word 12


def test_description_matches_only_unanalysed_vulnerabilities(db):
    sid = sbom(db, [{"name": "fastjson", "version": "1.2.80"}, {"name": "core"}])
    add_vuln(db, "CVE-NEW", "Alibaba Fastjson before 2.0 allows deserialization.")
    add_vuln(db, "CVE-ANALYSED", "Fastjson has a bug with CPE rows.")
    add_vuln(db, "CVE-REJ", "Rejected reason: fastjson duplicate.")
    add_vuln(db, "CVE-OTHER", "Unrelated core library issue.")
    db.execute(
        "INSERT INTO clean.affected_products (cve_id, vendor, product, vulnerable) "
        "VALUES ('CVE-ANALYSED', 'alibaba', 'fastjson', 'Y')"
    )
    assert dm.match_descriptions(db, sid) == 1
    rows = db.execute("SELECT cve_id, method, version_status FROM app.matches").fetchall()
    assert rows == [("CVE-NEW", "description", "unverified")]
    assert dm.match_descriptions(db, sid) == 0  # never duplicates a match


# --- Granite verification ------------------------------------------------------------------


class FakeClient:
    def __init__(self, replies):
        self.replies = list(replies)

    def chat(self, messages, max_tokens, temperature=0):
        return self.replies.pop(0), {"prompt_tokens": 1, "completion_tokens": 1}


def verdict(affected):
    return json.dumps({"affected": affected, "vendor": None, "product": None, "versions": None,
                       "confidence": "high", "reason": f"says {affected}"})  # fmt: skip


def test_granite_no_removes_the_match_and_verdicts_are_stored(db):
    sid = sbom(db, [{"name": "fastjson"}])
    add_vuln(db, "CVE-A", "fastjson flaw one")
    add_vuln(db, "CVE-B", "fastjson flaw two")
    dm.match_descriptions(db, sid)
    counts = verify_description_matches(db, sid, client=FakeClient([verdict("yes"), verdict("no")]))
    assert counts["yes"] == 1 and counts["no"] == 1
    left = [r[0] for r in db.execute("SELECT cve_id FROM app.matches").fetchall()]
    assert left == ["CVE-A"]
    assert db.execute("SELECT count(*) FROM app.match_checks").fetchone()[0] == 2


def test_granite_failure_stops_and_keeps_matches(db):
    class Broken:
        def chat(self, *a, **k):
            raise RuntimeError("budget")

    sid = sbom(db, [{"name": "fastjson"}])
    add_vuln(db, "CVE-A", "fastjson flaw")
    dm.match_descriptions(db, sid)
    counts = verify_description_matches(db, sid, client=Broken())
    assert counts["stopped"]
    assert db.execute("SELECT count(*) FROM app.matches").fetchone()[0] == 1


def test_granite_check_limit(db):
    sid = sbom(db, [{"name": "fastjson"}])
    for i in range(3):
        add_vuln(db, f"CVE-{i}", "fastjson flaw")
    dm.match_descriptions(db, sid)
    counts = verify_description_matches(db, sid, client=FakeClient([verdict("yes")] * 3), limit=2)
    assert counts["yes"] == 2


# --- the model-ranked queue ------------------------------------------------------------------


def bar(kind, label, value):
    return {"kind": kind, "label": label, "value": value}


@pytest.fixture
def ranked(db, tmp_path, monkeypatch):
    sid = sbom(db, [{"name": "zeta"}])
    preds = pd.DataFrame(
        {
            "cve_id": ["K", "HI", "LO", "OLD"],
            "confidence": ["exploited", "model", "model", "model"],
            "basis": ["kev", "snapshot_2026", "snapshot_2026", "latest_signals"],
            "score": [1.0, 0.9, 0.2, 0.5],
            "score_pct": [1.0, 0.99, 0.3, 0.7],
            "p_exploit": [None, 0.02, 0.001, 0.005],
            "model_pct": [None, 0.95, 0.4, 0.6],
            "safety_raw": [None, 1.9, 0.2, 0.5],
            "epss_pct": [None, 0.9, 0.2, 0.5],
            "any_exploit_code": [None, 1, 0, 0],
            "similarity_used": [None, True, True, False],
            "reasons": [
                [bar("vendor", "Its vendor: 3 earlier KEV entries", 0.2)],
                [bar("exploit", "Public exploit code (Nuclei)", 0.31)],
                [],
                [bar("exposure", "Weakness: Out-of-bounds Write", -0.04)],
            ],
            "signal": [None, "exploit_code", None, "score_jump"],
            "as_of": ["2025-01", "2026-09", "2026-09", "2025-12"],
        }
    )
    path = tmp_path / "predictions.parquet"
    preds.to_parquet(path)
    (tmp_path / "predictions_meta.json").write_text(json.dumps({"alpha": 0.25, "variant": "v"}))
    monkeypatch.setattr(config, "PREDICTIONS_PATH", path)
    for cve, cvss in (("K", 3.0), ("HI", 5.0), ("LO", 9.9), ("OLD", 7.0)):
        add_vuln(db, cve, f"desc {cve}", cvss)
        db.execute("INSERT INTO app.matches VALUES (?, 1, ?, 'cpe', 'in_range')", [sid, cve])
    db.execute("INSERT INTO clean.kev VALUES ('K', 'v', 'p', 'n', DATE '2025-01-02', 'Known', 'v')")
    return sid


def test_queue_uses_predictions(db, ranked):
    q = build_queue(db, ranked, today=date(2026, 11, 8))
    assert q["ranking"] == "model"
    assert [i["cve_id"] for i in q["items"]] == ["K", "HI", "OLD", "LO"]  # KEV, then score
    hi = q["items"][1]
    assert hi["reasons"] == [bar("exploit", "Public exploit code (Nuclei)", 0.31)]
    assert not hi["reasons_are_sample"] and hi["signal"] == "exploit_code"
    assert q["counts"]["warning_signs"] == 2
    assert hi["exploit_code"] and hi["basis"] == "snapshot_2026"
    assert q["scores"]["alpha"] == 0.25


def test_stale_flags(db, ranked):
    items = {i["cve_id"]: i for i in build_queue(db, ranked, today=date(2026, 11, 8))["items"]}
    assert not items["HI"]["stale"]  # Sep 2026: 39 days old
    assert items["OLD"]["stale"]  # Dec 2025
    assert not items["K"]["stale"]  # on KEV since Jan 2025: never stale
    assert month_end("2026-02") == date(2026, 2, 28)


def test_live_epss_reranks(db, ranked):
    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"cve": "LO", "epss": "0.9", "percentile": "0.999", "date": "d"}]}

    q = build_queue(db, ranked, live=True, today=date(2026, 11, 8), fetch=lambda p: Response())
    assert q["ranking"] == "model_live_epss"
    lo = next(i for i in q["items"] if i["cve_id"] == "LO")
    assert lo["epss_live_pct"] == pytest.approx(0.999)
    # 0.25 x 0.4 + 0.75 x pct(0.999 among [0.2, 0.5, 1.9]) = 0.1 + 0.75 x 2/3
    assert lo["score_live"] == pytest.approx(0.6)
    assert [i["cve_id"] for i in q["items"]] == ["K", "HI", "LO", "OLD"]


def test_live_epss_offline_keeps_stored_order(db, ranked):
    def offline(params):
        raise OSError("no network")

    q = build_queue(db, ranked, live=True, today=date(2026, 11, 8), fetch=offline)
    assert [i["cve_id"] for i in q["items"]] == ["K", "HI", "OLD", "LO"]


def test_rescore_skips_kev():
    live = {"epss": 0.5, "percentile": 0.9, "date": None}
    assert (
        epss_live.rescore({"on_kev": True, "model_pct": 0.5}, live, 0.25, [1.0])["score_live"]
        is None
    )
    assert epss_live.percentile_in([0.1, 0.2, 0.3], 0.2) == pytest.approx(2 / 3)


def test_one_request_upload_and_rank(client, ranked):
    bom = {"bomFormat": "CycloneDX", "components": [{"name": "zeta"}]}
    r = client.post("/api/sboms/fix-first", files={"file": ("b.json", json.dumps(bom))})
    assert r.status_code == 201
    body = r.json()
    assert body["ranking"] == "model"
    assert "items" in body and body["sbom_id"]
