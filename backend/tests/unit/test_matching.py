import json

from backend.services.matching import match_sbom
from backend.services.sbom import parse_cyclonedx, store_sbom


def add_product(
    db, cve, vendor, product, vulnerable="Y", version="*", start_inc=None, end_exc=None
):
    key = "".join(ch for ch in vendor.lower() if ch.isalnum())
    db.execute(
        "INSERT INTO clean.affected_products (cve_id, vendor, product, version, vulnerable, "
        "vendor_key, version_start_including, version_end_excluding) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [cve, vendor, product, version, vulnerable, key, start_inc, end_exc],
    )


def upload(db, components):
    raw = json.dumps({"bomFormat": "CycloneDX", "components": components}).encode()
    _, comps = parse_cyclonedx(raw)
    return store_sbom(db, "t", "t.json", comps)


def matches(db, sid):
    return {
        (r[0], r[1]): r[2]
        for r in db.execute(
            "SELECT component_id, cve_id, method FROM app.matches WHERE sbom_id = ?", [sid]
        ).fetchall()
    }


CPE = "cpe:2.3:a:{}:{}:1.0:*:*:*:*:*:*:*"


def test_vendor_and_product_match(db):
    add_product(db, "CVE-1", "Apache", "HTTP_Server")
    add_product(db, "CVE-2", "apache", "tomcat")
    sid = upload(db, [{"name": "a", "cpe": CPE.format("apache", "http_server")}])
    assert match_sbom(db, sid) == 1
    assert matches(db, sid) == {(1, "CVE-1"): "cpe"}


def test_alias_applied(db):
    db.execute("INSERT INTO clean.vendor_aliases VALUES ('Android', 'google', 1, 1)")
    add_product(db, "CVE-1", "google", "android")
    add_product(db, "CVE-2", "other", "android")
    sid = upload(db, [{"name": "Android", "cpe": CPE.format("android", "android")}])
    match_sbom(db, sid)
    assert matches(db, sid) == {(1, "CVE-1"): "cpe"}


def test_product_made_by_two_vendors_does_not_match_without_vendor(db):
    add_product(db, "CVE-1", "vendora", "widget")
    add_product(db, "CVE-2", "vendorb", "widget")
    sid = upload(db, [{"name": "widget", "purl": "pkg:npm/widget@1"}])
    assert match_sbom(db, sid) == 0


def test_single_vendor_product_matches_through_purl(db):
    add_product(db, "CVE-1", "vendora", "lodash")
    add_product(db, "CVE-2", "vendora", "lodash")
    sid = upload(db, [{"name": "lodash", "purl": "pkg:npm/lodash@4.17.20"}])
    assert match_sbom(db, sid) == 2
    assert set(matches(db, sid).values()) == {"purl_product_only"}


def test_misspelled_vendor_falls_back_to_product_only(db):
    add_product(db, "CVE-1", "realvendor", "thing")
    sid = upload(db, [{"name": "thing", "cpe": CPE.format("typo", "thing")}])
    match_sbom(db, sid)
    assert matches(db, sid) == {(1, "CVE-1"): "cpe_product_only"}


def test_vendor_match_blocks_product_only_rows(db):
    add_product(db, "CVE-1", "vendora", "thing")
    add_product(db, "CVE-2", "vendorb", "thing")
    sid = upload(db, [{"name": "thing", "cpe": CPE.format("vendora", "thing")}])
    match_sbom(db, sid)
    assert matches(db, sid) == {(1, "CVE-1"): "cpe"}


def test_non_vulnerable_rows_ignored(db):
    add_product(db, "CVE-1", "apache", "tomcat", vulnerable="N")
    sid = upload(db, [{"name": "a", "cpe": CPE.format("apache", "tomcat")}])
    assert match_sbom(db, sid) == 0


def test_name_method_and_rematch_replaces_rows(db):
    sid = upload(db, [{"name": "Widget", "supplier": {"name": "ACME Inc"}}])
    assert match_sbom(db, sid) == 0
    add_product(db, "CVE-2", "acmeinc", "widget")
    assert match_sbom(db, sid) == 1
    assert matches(db, sid) == {(1, "CVE-2"): "name"}
    db.execute("DELETE FROM clean.affected_products")
    assert match_sbom(db, sid) == 0
    assert matches(db, sid) == {}


def status(db, sid):
    return {
        r[0]: r[1]
        for r in db.execute(
            "SELECT cve_id, version_status FROM app.matches WHERE sbom_id = ?", [sid]
        ).fetchall()
    }


def test_out_of_range_dropped_and_in_range_marked(db):
    add_product(db, "CVE-IN", "acme", "widget", start_inc="1.0", end_exc="2.0")
    add_product(db, "CVE-OUT", "acme", "widget", end_exc="1.5")
    add_product(db, "CVE-EXACT", "acme", "widget", version="1.7")
    add_product(db, "CVE-ANY", "acme", "widget")
    comp = {"name": "w", "version": "1.7", "cpe": CPE.format("acme", "widget")}
    sid = upload(db, [comp])
    assert match_sbom(db, sid) == 3
    assert status(db, sid) == {
        "CVE-IN": "in_range",
        "CVE-EXACT": "in_range",
        "CVE-ANY": "in_range",
    }


def test_unversioned_component_is_unverified_unless_any_version(db):
    add_product(db, "CVE-RANGE", "acme", "widget", end_exc="2.0")
    add_product(db, "CVE-ANY", "acme", "widget")
    sid = upload(db, [{"name": "w", "cpe": CPE.format("acme", "widget").replace(":1.0:", ":*:")}])
    match_sbom(db, sid)
    assert status(db, sid) == {"CVE-RANGE": "unverified", "CVE-ANY": "in_range"}


def test_any_confirming_row_wins_over_unverified(db):
    # Same CVE listed twice: one row can't be checked against exact "1.7", one is any-version.
    add_product(db, "CVE-1", "acme", "widget", version="9.9")
    add_product(db, "CVE-1", "acme", "widget")
    sid = upload(db, [{"name": "w", "version": "1.7", "cpe": CPE.format("acme", "widget")}])
    assert match_sbom(db, sid) == 1
    assert status(db, sid) == {"CVE-1": "in_range"}
