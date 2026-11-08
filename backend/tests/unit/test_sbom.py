import json

import pytest

from backend.core.config import DEMO_DIR
from backend.services.sbom import (
    MAX_BYTES,
    SbomError,
    list_sboms,
    load_sbom,
    parse_cpe,
    parse_cyclonedx,
    parse_purl,
    store_sbom,
)


def bom(components, **extra):
    return json.dumps({"bomFormat": "CycloneDX", "components": components, **extra}).encode()


def test_parse_cpe_23():
    assert parse_cpe("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*") == (
        "apache",
        "http_server",
        "2.4.58",
    )


def test_parse_cpe_wildcards_and_escapes():
    assert parse_cpe(r"cpe:2.3:a:foo:ba\-r:*:*:*:*:*:*:*:*") == ("foo", "ba-r", None)
    assert parse_cpe("cpe:2.3:a:foo:bar:-:*:*:*:*:*:*:*") == ("foo", "bar", None)


def test_parse_cpe_22():
    assert parse_cpe("cpe:/a:apache:tomcat:10.1.15") == ("apache", "tomcat", "10.1.15")
    assert parse_cpe("cpe:/o:linux:linux_kernel") == ("linux", "linux_kernel", None)


@pytest.mark.parametrize("bad", ["", "nonsense", "cpe:2.3:a", None, 5])
def test_parse_cpe_invalid(bad):
    assert parse_cpe(bad) is None


def test_parse_purl_maven():
    assert parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1") == (
        "apache",
        "log4j-core",
        "2.14.1",
    )


def test_parse_purl_maven_non_tld():
    assert parse_purl("pkg:maven/commons-io/commons-io@2.11.0") == (
        "commons-io",
        "commons-io",
        "2.11.0",
    )
    assert parse_purl("pkg:maven/acme.tools/widget@1") == ("acme", "widget", "1")


def test_parse_purl_npm_and_pypi():
    assert parse_purl("pkg:npm/lodash@4.17.20") == (None, "lodash", "4.17.20")
    assert parse_purl("pkg:pypi/django@4.2.0") == (None, "django", "4.2.0")
    assert parse_purl("pkg:npm/%40angular/core@16.0.0") == ("angular", "core", "16.0.0")
    assert parse_purl("pkg:npm/@babel/core@7.0.0?foo=bar#sub") == ("babel", "core", "7.0.0")


def test_parse_purl_invalid():
    assert parse_purl("nope") is None
    assert parse_purl("pkg:npm") is None


def test_components_cpe_first_then_purl_then_fallback():
    raw = bom(
        [
            {
                "name": "A",
                "cpe": "cpe:2.3:a:v1:p1:1.0:*:*:*:*:*:*:*",
                "purl": "pkg:npm/zzz@9",
            },
            {"name": "B", "purl": "pkg:pypi/django@4.2.0"},
            {"name": "C", "supplier": {"name": "Sup"}, "version": "3"},
            {"name": "D", "publisher": "Pub"},
            {"name": "E", "group": "grp"},
        ],
        metadata={"component": {"name": "My App"}},
    )
    name, comps = parse_cyclonedx(raw)
    assert name == "My App"
    a, b, c, d, e = comps
    assert (a["vendor"], a["product"], a["version"]) == ("v1", "p1", "1.0")
    assert (b["vendor"], b["product"], b["version"]) == (None, "django", "4.2.0")
    assert (c["vendor"], c["product"], c["version"]) == ("Sup", "C", "3")
    assert d["vendor"] == "Pub"
    assert e["vendor"] == "grp" and e["group"] == "grp"
    assert [x["component_id"] for x in comps] == [1, 2, 3, 4, 5]


def test_explicit_version_beats_identifier_version():
    _, comps = parse_cyclonedx(bom([{"name": "A", "version": "2", "purl": "pkg:npm/a@1"}]))
    assert comps[0]["version"] == "2"


def test_nested_components_depth_first_and_nameless_skipped():
    raw = bom(
        [
            {"name": "a", "components": [{"name": "a1", "components": [{"name": "a1x"}]}]},
            {"version": "1", "components": [{"name": "orphan-child"}]},
            {"name": "b"},
        ]
    )
    _, comps = parse_cyclonedx(raw)
    assert [c["name"] for c in comps] == ["a", "a1", "a1x", "orphan-child", "b"]
    assert [c["component_id"] for c in comps] == [1, 2, 3, 4, 5]


@pytest.mark.parametrize(
    "raw",
    [
        b"{not json",
        b"\xff\xfe",
        b"[1, 2]",
        b'{"bomFormat": "SPDX"}',
        b'{"bomFormat": "CycloneDX"}',
        b'{"bomFormat": "CycloneDX", "components": [{"version": "1"}]}',
        b" " * (MAX_BYTES + 1),
    ],
)
def test_parse_errors(raw):
    with pytest.raises(SbomError):
        parse_cyclonedx(raw)


def test_demo_file_parses():
    name, comps = parse_cyclonedx((DEMO_DIR / "acme_sbom.cdx.json").read_bytes())
    assert name == "Acme Logistics Platform"
    assert len(comps) == 22
    log4j = next(c for c in comps if c["name"] == "Log4j core")
    assert (log4j["vendor"], log4j["product"]) == ("apache", "log4j")


def test_store_load_list(db):
    _, comps = parse_cyclonedx(bom([{"name": "a", "group": "g"}, {"name": "b"}]))
    sid = store_sbom(db, "App", "f.json", comps)
    assert len(sid) == 12
    loaded = load_sbom(db, sid)
    assert loaded["component_count"] == 2
    assert [c["name"] for c in loaded["components"]] == ["a", "b"]
    assert loaded["components"][0]["group"] == "g"
    assert load_sbom(db, "nope") is None
    sid2 = store_sbom(db, "App2", "g.json", comps)
    assert [s["sbom_id"] for s in list_sboms(db)] == [sid2, sid]
