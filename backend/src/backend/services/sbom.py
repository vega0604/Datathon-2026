"""CycloneDX parsing and SBOM storage. Plain functions; no FastAPI imports."""

import json
import uuid
from datetime import UTC, datetime
from urllib.parse import unquote

import pandas as pd

MAX_BYTES = 5_000_000
_TLD_PREFIXES = {"org", "com", "io", "net", "dev"}


class SbomError(ValueError):
    """Raised with a message that is safe to show to the user."""


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.replace("\\", "").strip()
    return None if value in ("", "*", "-") else value


def parse_cpe(cpe: str) -> tuple[str | None, str | None, str | None] | None:
    """Return (vendor, product, version) from a CPE 2.3 or 2.2 string, else None."""
    if not isinstance(cpe, str):
        return None
    cpe = cpe.strip()
    parts = cpe.split(":")
    if cpe.lower().startswith("cpe:2.3:") and len(parts) >= 6:
        v, p, ver = parts[3], parts[4], parts[5]
    elif cpe.lower().startswith("cpe:/") and len(parts) >= 3:
        v = parts[2]
        p = parts[3] if len(parts) > 3 else ""
        ver = parts[4] if len(parts) > 4 else ""
    else:
        return None
    return _clean(v), _clean(p), _clean(ver)


def _purl_vendor(namespace: list[str]) -> str | None:
    if not namespace:
        return None
    first = namespace[0].lstrip("@")
    pieces = [x for x in first.split(".") if x]
    if not pieces:
        return None
    if len(pieces) > 1 and pieces[0].lower() in _TLD_PREFIXES:
        return pieces[1]
    return pieces[0]


def parse_purl(purl: str) -> tuple[str | None, str | None, str | None] | None:
    """Return (vendor, product, version) from `pkg:type/namespace/name@version?q#sub`."""
    if not isinstance(purl, str) or not purl.strip().lower().startswith("pkg:"):
        return None
    rest = purl.strip()[4:].split("#", 1)[0].split("?", 1)[0].strip("/")
    segments = rest.split("/")
    if len(segments) < 2:
        return None
    name, _, version = segments[-1].partition("@")
    name = unquote(name)
    if not name:
        return None
    namespace = [unquote(s) for s in segments[1:-1]]
    return _purl_vendor(namespace), name, unquote(version) or None


def _walk(components: list, out: list) -> None:
    for c in components:
        if not isinstance(c, dict):
            continue
        if isinstance(c.get("name"), str) and c["name"].strip():
            out.append(c)
        if isinstance(c.get("components"), list):
            _walk(c["components"], out)


def _text(value) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def parse_cyclonedx(raw: bytes) -> tuple[str | None, list[dict]]:
    if len(raw) > MAX_BYTES:
        raise SbomError(f"File is too large (limit {MAX_BYTES // 1_000_000} MB).")
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise SbomError("File is not valid JSON.") from e
    if not isinstance(doc, dict):
        raise SbomError("SBOM must be a JSON object.")
    if doc.get("bomFormat") != "CycloneDX":
        raise SbomError('Only CycloneDX JSON is supported (bomFormat must be "CycloneDX").')

    flat: list[dict] = []
    if isinstance(doc.get("components"), list):
        _walk(doc["components"], flat)

    components = []
    for i, c in enumerate(flat, 1):
        name = c["name"].strip()
        cpe, purl, group = _text(c.get("cpe")), _text(c.get("purl")), _text(c.get("group"))
        from_cpe = parse_cpe(cpe) if cpe else None
        from_purl = parse_purl(purl) if purl else None
        if from_cpe and (from_cpe[0] or from_cpe[1]):
            vendor, product = from_cpe[0], from_cpe[1]
        elif from_purl and from_purl[1]:
            vendor, product = from_purl[0], from_purl[1]
        else:
            supplier = c.get("supplier")
            supplier_name = supplier.get("name") if isinstance(supplier, dict) else None
            vendor = _text(supplier_name) or _text(c.get("publisher")) or group
            product = name
        version = (
            _text(c.get("version"))
            or (from_cpe[2] if from_cpe else None)
            or (from_purl[2] if from_purl else None)
        )
        components.append(
            {
                "component_id": i,
                "name": name,
                "group": group,
                "version": version,
                "purl": purl,
                "cpe": cpe,
                "vendor": vendor,
                "product": product,
            }
        )
    if not components:
        raise SbomError("SBOM has no usable components.")

    meta = doc.get("metadata")
    main = meta.get("component") if isinstance(meta, dict) else None
    sbom_name = _text(main.get("name")) if isinstance(main, dict) else None
    return sbom_name, components


def store_sbom(con, name: str, filename: str | None, components: list[dict]) -> str:
    sbom_id = uuid.uuid4().hex[:12]
    now = datetime.now(UTC).replace(tzinfo=None)
    con.execute(
        "INSERT INTO app.sboms VALUES ($id, $name, $filename, $ts, $n)",
        {"id": sbom_id, "name": name, "filename": filename, "ts": now, "n": len(components)},
    )
    df = pd.DataFrame(
        [
            {
                "sbom_id": sbom_id,
                "component_id": c["component_id"],
                "name": c["name"],
                "group_name": c["group"],
                "version": c["version"],
                "purl": c["purl"],
                "cpe": c["cpe"],
                "vendor": c["vendor"],
                "product": c["product"],
            }
            for c in components
        ]
    )
    con.register("_new_components", df)
    try:
        con.execute("INSERT INTO app.components SELECT * FROM _new_components")
    finally:
        con.unregister("_new_components")
    return sbom_id


_SUMMARY = ["sbom_id", "name", "filename", "uploaded_at", "component_count"]


def load_sbom(con, sbom_id: str) -> dict | None:
    row = con.execute(
        f"SELECT {', '.join(_SUMMARY)} FROM app.sboms WHERE sbom_id = ?", [sbom_id]
    ).fetchone()
    if row is None:
        return None
    out = dict(zip(_SUMMARY, row, strict=True))
    cur = con.execute(
        "SELECT component_id, name, group_name, version, purl, cpe, vendor, product "
        "FROM app.components WHERE sbom_id = ? ORDER BY component_id",
        [sbom_id],
    )
    cols = [d[0] for d in cur.description]
    comps = []
    for r in cur.fetchall():
        c = dict(zip(cols, r, strict=True))
        c["group"] = c.pop("group_name")
        comps.append(c)
    out["components"] = comps
    return out


def component_summaries(con, sbom_id: str) -> list[dict]:
    """Components with their matched CVE count and how many of those are on KEV."""
    cur = con.execute(
        """
        SELECT c.component_id, c.name, c.group_name AS "group", c.version, c.purl, c.cpe,
               c.vendor, c.product,
               count(DISTINCT m.cve_id) AS matched_cves,
               count(DISTINCT k.cve_id) AS kev_cves
        FROM app.components c
        LEFT JOIN app.matches m ON m.sbom_id = c.sbom_id AND m.component_id = c.component_id
        LEFT JOIN clean.kev k ON k.cve_id = m.cve_id
        WHERE c.sbom_id = ?
        GROUP BY ALL
        ORDER BY c.component_id
        """,
        [sbom_id],
    )
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


def list_sboms(con) -> list[dict]:
    rows = con.execute(
        f"SELECT {', '.join(_SUMMARY)} FROM app.sboms ORDER BY uploaded_at DESC, sbom_id"
    ).fetchall()
    return [dict(zip(_SUMMARY, r, strict=True)) for r in rows]
