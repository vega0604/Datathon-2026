"""The Fix-First queue for one SBOM. Plain functions; no FastAPI.

With data/features/predictions.parquet (backend.modeling.serving): vulnerabilities on KEV
first, then the submitted ranking's score (the LightGBM model rank-blended with the safety
ranker), which is on one scale for every vulnerability; ties by CVSS, then CVE id. Each
item carries its reasons, the month its scores describe (as_of, flagged stale when old),
how it was matched, and Granite's verdict for description-only matches. EPSS_LIVE re-scores
with today's EPSS from FIRST.

Without predictions.parquet: the placeholder ranking (KEV, EPSS percentile, CVSS).
"""

import json
from datetime import date

from backend.core import config
from backend.services import epss_live

_MATCHED = """
matched AS (
    SELECT m.cve_id,
           list_sort(list_distinct(list(c.name))) AS components,
           list_sort(list_distinct(list(m.method))) AS match_methods,
           CASE WHEN bool_or(m.version_status = 'in_range') THEN 'in_range'
                ELSE 'unverified' END AS version_status
    FROM app.matches m
    JOIN app.components c ON c.sbom_id = m.sbom_id AND c.component_id = m.component_id
    WHERE m.sbom_id = $sbom_id
    GROUP BY m.cve_id
)"""

_SIGNALS = """
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
)"""

# Placeholder ranking (no predictions.parquet): KEV first, then the EPSS percentile of the
# most recent signal, then CVSS, then CVE id for a stable order.
_PLACEHOLDER_SQL = f"""
WITH {_MATCHED}, {_SIGNALS},
joined AS (
    SELECT m.cve_id, m.components, m.match_methods, m.version_status,
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


def _model_sql(predictions: str, paged: bool) -> str:
    page = "LIMIT $limit OFFSET $offset" if paged else ""
    return f"""
WITH {_MATCHED}, {_SIGNALS},
checks AS (
    SELECT cve_id,
           CASE WHEN bool_or(affected = 'yes') THEN 'yes'
                WHEN bool_or(affected = 'unknown') THEN 'unknown' ELSE 'no' END AS granite_verdict,
           min(reason) AS granite_reason
    FROM app.match_checks WHERE sbom_id = $sbom_id GROUP BY cve_id
),
joined AS (
    SELECT m.cve_id, m.components, m.match_methods, m.version_status,
           k.cve_id IS NOT NULL AS on_kev,
           k.date_added AS kev_date_added,
           coalesce(k.known_ransomware_use = 'Known', false) AS known_ransomware,
           p.score, p.score_pct, p.p_exploit, p.model_pct, p.confidence, p.basis, p.as_of,
           p.similarity_used, coalesce(p.reasons, []) AS reasons,
           s.epss,
           coalesce(s.exploit_code, p.any_exploit_code = 1, false) AS exploit_code,
           coalesce(v.cvss3_score, v.cvss4_score) AS cvss_score,
           v.published,
           v.description,
           c.granite_verdict, c.granite_reason
    FROM matched m
    LEFT JOIN {predictions} p ON p.cve_id = m.cve_id
    LEFT JOIN scored s ON s.cve_id = m.cve_id
    LEFT JOIN clean.kev k ON k.cve_id = m.cve_id
    LEFT JOIN vulnerabilities v ON v.cve_id = m.cve_id
    LEFT JOIN checks c ON c.cve_id = m.cve_id
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
SELECT * FROM ranked ORDER BY rank {page}
"""


def predictions_source() -> str | None:
    path = config.PREDICTIONS_PATH
    return f"read_parquet('{path.as_posix()}')" if path.exists() else None


def predictions_meta() -> dict:
    """What serving recorded about the scores (alpha, build time, signals through)."""
    path = config.PREDICTIONS_PATH.with_name("predictions_meta.json")
    return json.loads(path.read_text()) if path.exists() else {}


_SAFETY_CACHE: dict[str, list[float]] = {}


def safety_distribution(con, predictions: str) -> list[float]:
    """Sorted stored safety scores of every non-KEV vulnerability (cached per file)."""
    key = f"{predictions}:{config.PREDICTIONS_PATH.stat().st_mtime}"
    if key not in _SAFETY_CACHE:
        values = con.execute(
            f"SELECT safety_raw FROM {predictions} WHERE safety_raw IS NOT NULL ORDER BY 1"
        ).fetchall()
        _SAFETY_CACHE.clear()
        _SAFETY_CACHE[key] = [v[0] for v in values]
    return _SAFETY_CACHE[key]


def month_end(month: str | None) -> date | None:
    if not month:
        return None
    year, mon = int(month[:4]), int(month[5:7])
    nxt = date(year + mon // 12, mon % 12 + 1, 1)
    return date.fromordinal(nxt.toordinal() - 1)


def mark_stale(rows: list[dict], today: date) -> None:
    for r in rows:
        end = month_end(r.get("as_of"))
        r["stale"] = end is not None and (today - end).days > config.SCORE_STALE_DAYS


def _rows(cur) -> list[dict]:
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


def build_queue(
    con,
    sbom_id: str,
    limit: int = 100,
    offset: int = 0,
    live: bool | None = None,
    today: date | None = None,
    fetch=None,
) -> dict:
    """One page of the SBOM's Fix-First queue. `fetch` replaces the FIRST call in tests."""
    predictions = predictions_source()
    params = {"sbom_id": sbom_id, "limit": limit, "offset": offset}
    if predictions is None:
        rows = _rows(con.execute(_PLACEHOLDER_SQL, params))
        out = {"ranking": "epss_placeholder", "scores": {}}
    else:
        live = config.EPSS_LIVE if live is None else live
        meta = predictions_meta()
        if not live:
            rows = _rows(con.execute(_model_sql(predictions, paged=True), params))
            ranking = "model"
        else:
            rows = _rows(con.execute(_model_sql(predictions, paged=False), {"sbom_id": sbom_id}))
            rows = _rerank_live(con, rows, predictions, float(meta.get("alpha", 1.0)), fetch)
            rows = rows[offset : offset + limit]
            ranking = "model_live_epss"
        mark_stale(rows, today or date.today())
        out = {"ranking": ranking, "scores": meta}
    if rows:
        total = rows[0]["total"]
    else:  # a page past the end has no rows to read the total from
        total = con.execute(
            "SELECT count(DISTINCT cve_id) FROM app.matches WHERE sbom_id = ?", [sbom_id]
        ).fetchone()[0]
    for r in rows:
        r.pop("total", None)
    return {"sbom_id": sbom_id, "total": total, "items": rows, **out}


def _rerank_live(con, rows: list[dict], predictions: str, alpha: float, fetch) -> list[dict]:
    live = epss_live.fetch_epss([r["cve_id"] for r in rows], get=fetch)
    if live:
        safety_sorted = safety_distribution(con, predictions)
        for r in rows:
            if r["cve_id"] in live:
                r.update(epss_live.rescore(r, live[r["cve_id"]], alpha, safety_sorted))
    for r in rows:
        r.setdefault("score_live", None)

    def key(r):
        score = r["score_live"] if r.get("score_live") is not None else r.get("score")
        return (
            not r["on_kev"],
            -(score if score is not None else -1.0),
            -(r["cvss_score"] if r["cvss_score"] is not None else -1.0),
            r["cve_id"],
        )

    rows.sort(key=key)
    for i, r in enumerate(rows, 1):
        r["rank"] = i
    return rows
