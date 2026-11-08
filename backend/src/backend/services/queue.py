"""The Fix-First queue for one SBOM. Plain functions; no FastAPI."""

# Placeholder ranking until the model lands (SHE-8): KEV first, then the EPSS percentile of the
# most recent signal, then CVSS, then CVE id for a stable order.
_QUEUE_SQL = """
WITH matched AS (
    SELECT m.cve_id,
           list_sort(list_distinct(list(c.name))) AS components,
           CASE WHEN bool_or(m.version_status = 'in_range') THEN 'in_range'
                ELSE 'unverified' END AS version_status
    FROM app.matches m
    JOIN app.components c ON c.sbom_id = m.sbom_id AND c.component_id = m.component_id
    WHERE m.sbom_id = $sbom_id
    GROUP BY m.cve_id
),
board_pct AS (
    -- percentile over the whole scoreboard within its snapshot month
    SELECT cve_id, snapshot_month,
           percent_rank() OVER (PARTITION BY snapshot_month ORDER BY epss) AS epss_pct
    FROM scoreboard_2026
    WHERE epss IS NOT NULL
),
board AS (
    SELECT s.cve_id, s.epss, p.epss_pct,
           (coalesce(s.exploitdb, 0) + coalesce(s.metasploit, 0)
            + coalesce(s.nuclei, 0) + coalesce(s.poc_github, 0)) > 0 AS exploit_code
    FROM scoreboard_2026 s
    LEFT JOIN board_pct p ON p.cve_id = s.cve_id AND p.snapshot_month = s.snapshot_month
    WHERE s.cve_id IN (SELECT cve_id FROM matched)
    QUALIFY row_number() OVER (PARTITION BY s.cve_id ORDER BY s.snapshot_month DESC) = 1
),
signal AS (
    -- filter to matched ids before the window function: exploit_signals has 6M rows
    SELECT cve_id, epss, epss_pct,
           (coalesce(exploitdb, 0) + coalesce(metasploit, 0)
            + coalesce(nuclei, 0) + coalesce(poc_github, 0)) > 0 AS exploit_code
    FROM clean.exploit_signals
    WHERE cve_id IN (SELECT cve_id FROM matched)
      AND cve_id NOT IN (SELECT cve_id FROM board)
    QUALIFY row_number() OVER (PARTITION BY cve_id ORDER BY month DESC) = 1
),
scored AS (
    SELECT * FROM board
    UNION ALL
    SELECT * FROM signal
),
joined AS (
    SELECT m.cve_id, m.components, m.version_status,
           k.cve_id IS NOT NULL AS on_kev,
           k.date_added AS kev_date_added,
           coalesce(k.known_ransomware_use = 'Known', false) AS known_ransomware,
           s.epss_pct AS score,
           s.epss,
           coalesce(s.exploit_code, false) AS exploit_code,
           coalesce(v.cvss3_score, v.cvss4_score) AS cvss_score,
           v.published,
           v.description
    FROM matched m
    LEFT JOIN scored s ON s.cve_id = m.cve_id
    LEFT JOIN clean.kev k ON k.cve_id = m.cve_id
    LEFT JOIN vulnerabilities v ON v.cve_id = m.cve_id
),
ranked AS (
    SELECT row_number() OVER (
               ORDER BY on_kev DESC, score DESC NULLS LAST, cvss_score DESC NULLS LAST, cve_id
           ) AS rank,
           row_number() OVER (ORDER BY cvss_score DESC NULLS LAST, cve_id) AS cvss_rank,
           count(*) OVER () AS total,
           *
    FROM joined
)
SELECT * FROM ranked ORDER BY rank LIMIT $limit OFFSET $offset
"""


def build_queue(con, sbom_id: str, limit: int = 100, offset: int = 0) -> dict:
    cur = con.execute(_QUEUE_SQL, {"sbom_id": sbom_id, "limit": limit, "offset": offset})
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]
    if rows:
        total = rows[0]["total"]
    else:  # a page past the end has no rows to read the total from
        total = con.execute(
            "SELECT count(DISTINCT cve_id) FROM app.matches WHERE sbom_id = ?", [sbom_id]
        ).fetchone()[0]
    for r in rows:
        del r["total"]
    return {"sbom_id": sbom_id, "ranking": "epss_placeholder", "total": total, "items": rows}
