"""Components of one SBOM with their risk (the Your software screens). Plain functions.

Each component gets a `risk` object built from its rows in the Fix-First queue: CVE count,
severity mix, highest CVSS and EPSS, KEV entries, the three highest-ranked CVEs, and the
version that fixes every matched range (`fixed_in`). Components are ranked by their
highest-ranked CVE.
"""

from datetime import date
from functools import cmp_to_key

from backend.services.matching import candidates_sql
from backend.services.queue import (
    cached_queue,
    display_vendor,
    predictions_meta,
    vendor_names,
)
from backend.services.sbom import load_sbom
from backend.services.versions import compare, in_range

PARTS = {"a": "application", "o": "operating system", "h": "hardware"}
SEVERITIES = ("critical", "high", "medium", "low", "none")


def cpe_part(cpe: str | None) -> str | None:
    """application / operating system / hardware from a CPE 2.3 or 2.2 part letter."""
    if not cpe:
        return None
    parts = cpe.split(":")
    if cpe.lower().startswith("cpe:2.3:") and len(parts) > 2:
        letter = parts[2]
    elif cpe.lower().startswith("cpe:/") and len(parts) > 1:
        letter = parts[1].lstrip("/")
    else:
        return None
    return PARTS.get(letter.lower()[:1])


def newest(versions: list[str]) -> str | None:
    return max(versions, key=cmp_to_key(compare)) if versions else None


def fixed_versions(con, sbom_id: str) -> dict[int, str]:
    """component_id -> the lowest version past every affected range that matched it (the
    highest 'fixed before' bound above its version). Only ranges with an end bound count."""
    fixes: dict[int, list[str]] = {}
    for cid, version, _method, _cve, exact, si, se, ei, ee in con.execute(
        candidates_sql(), {"sbom_id": sbom_id}
    ).fetchall():
        if not ee or in_range(version, exact, si, se, ei, ee) is not True:
            continue
        if version and compare(ee, version) <= 0:
            continue
        fixes.setdefault(cid, []).append(ee)
    return {cid: newest(v) for cid, v in fixes.items() if v}


def risk(rows: list[dict], fixed_in: str | None) -> dict:
    by_rank = sorted(rows, key=lambda r: r["rank"])
    sev = {s: 0 for s in SEVERITIES}
    for r in rows:
        sev[r["severity"]] += 1
    epss = [r["epss"] for r in rows if r.get("epss") is not None]
    kev = sorted(
        ({"cve_id": r["cve_id"], "date_added": r["kev_date_added"], "name": r.get("kev_name")}
         for r in rows if r.get("on_kev")),
        key=lambda k: (k["date_added"] or date.max, k["cve_id"]),
    )  # fmt: skip
    top = [
        {
            "cve_id": r["cve_id"],
            "cvss": r["cvss_score"],
            "severity": r["severity"],
            "published": r.get("published"),
            "summary": r.get("description"),
            "epss": r.get("epss"),
            "kev": (
                {
                    "date_added": r["kev_date_added"],
                    "name": r.get("kev_name"),
                    "ransomware": bool(r.get("known_ransomware")),
                }
                if r.get("on_kev")
                else None
            ),
        }
        for r in by_rank[:3]
    ]
    return {
        "cve_count": len(rows),
        "severity": sev,
        "max_cvss": max((r["cvss_score"] for r in rows), default=0.0),
        "epss_max": max(epss) if epss else None,
        "fixed_in": fixed_in,
        "kev": kev,
        "top": top,
    }


def components_view(con, sbom_id: str) -> dict | None:
    """The SBOM with every component and its risk, components ranked by their worst CVE."""
    sbom = load_sbom(con, sbom_id)
    if sbom is None:
        return None
    spec = con.execute("SELECT spec_version FROM app.sboms WHERE sbom_id = ?", [sbom_id]).fetchone()
    queue = {r["cve_id"]: r for r in cached_queue(con, sbom_id)["items"]}
    pairs: dict[int, list[str]] = {}
    methods: dict[int, set[str]] = {}
    for cid, cve, method in con.execute(
        "SELECT component_id, cve_id, method FROM app.matches WHERE sbom_id = ?", [sbom_id]
    ).fetchall():
        pairs.setdefault(cid, []).append(cve)
        if method:
            methods.setdefault(cid, set()).add(method)
    fixes = fixed_versions(con, sbom_id)
    names = vendor_names(con)
    comps = []
    for c in sbom["components"]:
        rows = [queue[cve] for cve in pairs.get(c["component_id"], []) if cve in queue]
        comps.append(
            {
                "component_id": c["component_id"],
                "name": c["name"],
                "version": c["version"],
                "vendor": display_vendor(c["vendor"] or c["group"], names),
                "cpe": c["cpe"],
                "purl": c["purl"],
                "part": cpe_part(c["cpe"]),
                "match_methods": sorted(methods.get(c["component_id"], ())),
                "risk": risk(rows, fixes.get(c["component_id"])),
                "_best": min((r["rank"] for r in rows), default=None),
            }
        )
    order = sorted(comps, key=lambda c: (c["_best"] is None, c["_best"] or 0, c["component_id"]))
    for i, c in enumerate(order, 1):
        c["rank"] = i
        del c["_best"]
    built = predictions_meta().get("built_at")
    return {
        "sbom_id": sbom_id,
        "name": sbom["name"],
        "filename": sbom["filename"],
        "uploaded_at": sbom["uploaded_at"],
        "component_count": sbom["component_count"],
        "spec_version": spec[0] if spec else None,
        "risk_checked": date.fromisoformat(built[:10]) if built else date.today(),
        "cve_total": len(queue),
        "components": comps,
    }
