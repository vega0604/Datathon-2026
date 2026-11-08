"""Match SBOM components to CVEs through NIST's product lists. Plain functions; no FastAPI."""

import pandas as pd

from backend.services.versions import in_range

# Same rule as the pipeline's vendor_key_sql (SHE-22): lower case, letters and digits only.
# Reimplemented here because the API never imports `pipeline`.
_KEY = "nullif(regexp_replace(lower({col}), '[^a-z0-9]', '', 'g'), '')"


def _key(col: str) -> str:
    return _KEY.format(col=col)


def candidates_sql() -> str:
    """One row per (component, product row) that name-matches. Parameter: $sbom_id."""
    return f"""
    WITH alias AS (
        SELECT {_key("kev_vendor")} AS kev_key, min({_key("cpe_vendor")}) AS cpe_key
        FROM clean.vendor_aliases
        GROUP BY 1
    ),
    comp0 AS (
        SELECT
            component_id,
            version AS component_version,
            {_key("vendor")} AS vendor_key0,
            {_key("product")} AS product_key,
            CASE
                WHEN cpe IS NOT NULL AND lower(cpe) LIKE 'cpe:%' THEN 'cpe'
                WHEN purl IS NOT NULL AND lower(purl) LIKE 'pkg:%' THEN 'purl'
                ELSE 'name'
            END AS method
        FROM app.components
        WHERE sbom_id = $sbom_id
    ),
    comp AS (
        SELECT c.component_id, c.component_version, c.product_key, c.method,
               coalesce(a.cpe_key, c.vendor_key0) AS vendor_key
        FROM comp0 c
        LEFT JOIN alias a ON a.kev_key = c.vendor_key0
        WHERE c.product_key IS NOT NULL
    ),
    prod_rows AS (
        SELECT cve_id, vendor_key, {_key("product")} AS product_key, version,
               version_start_including, version_start_excluding,
               version_end_including, version_end_excluding
        FROM clean.affected_products
        WHERE vulnerable = 'Y'
          AND {_key("product")} IN (SELECT product_key FROM comp)
    ),
    product_vendors AS (
        SELECT product_key, count(DISTINCT vendor_key) AS n_vendors
        FROM prod_rows
        GROUP BY product_key
    ),
    vendor_hit AS (
        SELECT DISTINCT c.component_id
        FROM comp c
        JOIN prod_rows p ON p.product_key = c.product_key AND p.vendor_key = c.vendor_key
    )
    SELECT
        c.component_id,
        c.component_version,
        CASE WHEN p.vendor_key = c.vendor_key THEN c.method
             ELSE c.method || '_product_only' END AS method,
        p.cve_id,
        p.version,
        p.version_start_including,
        p.version_start_excluding,
        p.version_end_including,
        p.version_end_excluding
    FROM comp c
    JOIN prod_rows p ON p.product_key = c.product_key
    JOIN product_vendors v ON v.product_key = c.product_key
    WHERE p.vendor_key = c.vendor_key
       OR (v.n_vendors = 1
           AND c.component_id NOT IN (SELECT component_id FROM vendor_hit))
    """


def match_sbom(con, sbom_id: str) -> int:
    """Replace the SBOM's rows in app.matches. Returns the number of (component, cve) pairs.

    Rows whose version range excludes the component are dropped. A pair is `in_range` if any
    row confirmed it, else `unverified` (the component or the row had no usable version).
    """
    params = {"sbom_id": sbom_id}
    con.execute("DELETE FROM app.matches WHERE sbom_id = $sbom_id", params)
    # Plain tuples (NULL -> None) are much faster to loop over than a pandas frame.
    cand = con.execute(candidates_sql(), params).fetchall()

    best: dict[tuple[int, str], list] = {}  # (component_id, cve_id) -> [method, confirmed]
    for cid, cver, method, cve, exact, si, se, ei, ee in cand:
        ok = in_range(cver, exact, si, se, ei, ee)
        if ok is False:
            continue
        entry = best.setdefault((cid, cve), [method, False])
        entry[0] = min(entry[0], method)
        entry[1] = entry[1] or ok is True
    if not best:
        return 0

    df = pd.DataFrame(
        {
            "sbom_id": sbom_id,
            "component_id": [k[0] for k in best],
            "cve_id": [k[1] for k in best],
            "method": [v[0] for v in best.values()],
            "version_status": ["in_range" if v[1] else "unverified" for v in best.values()],
        }
    )
    con.register("_new_matches", df)
    try:
        con.execute("INSERT INTO app.matches SELECT * FROM _new_matches")
    finally:
        con.unregister("_new_matches")
    return len(df)
