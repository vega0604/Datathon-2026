"""The Fix-First queue for one SBOM. Plain functions; no FastAPI.

With data/features/predictions.parquet (backend.modeling.serving): vulnerabilities on KEV
first, then the submitted ranking's score (the LightGBM model rank-blended with the safety
ranker), which is on one scale for every vulnerability; ties by CVSS, then CVE id.

Every row carries what the Fix first table and its detail panel show (see the frontend API
handoff): the display component, severity, the warning sign, status and Linear ticket, an
"in plain words" explanation, three reason bars, and the KEV / weakness facts. Counts
cover the whole queue. EPSS_LIVE re-scores with today's EPSS from FIRST.

Without predictions.parquet: the placeholder ranking (KEV, EPSS percentile, CVSS).
"""

import json
import re
import time
from datetime import date

from backend.core import config
from backend.services import epss_live

DEFAULT_LIMIT = 1000

_MATCHED = """
matched AS (
    SELECT m.cve_id,
           list_sort(list_distinct(list(c.name))) AS components,
           list_sort(list_distinct(list(m.method))) AS match_methods,
           CASE WHEN bool_or(m.version_status = 'in_range') THEN 'in_range'
                ELSE 'unverified' END AS version_status,
           -- the component to show: a version-confirmed match first, then the lowest id
           list_sort(list({'unconfirmed': m.version_status <> 'in_range',
                           'id': c.component_id, 'name': c.name,
                           'vendor': coalesce(c.vendor, c.group_name)}))[1] AS shown,
           count(DISTINCT c.component_id) AS assets
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

# Fields every row gets in both modes: KEV and weakness facts, status, ticket, cached
# Granite explanation.
_COMMON = """
           k.cve_id IS NOT NULL AS on_kev,
           k.date_added AS kev_date_added,
           k.name AS kev_name,
           coalesce(k.known_ransomware_use = 'Known', false) AS known_ransomware,
           coalesce(v.cvss3_score, v.cvss4_score) AS cvss_raw,
           v.published,
           v.description,
           nullif(trim(split_part(coalesce(v.cwe_ids, ''), ';', 1)), '') AS cwe_id,
           w.name AS cwe_name,
           coalesce(qs.status, 'to_do') AS status,
           t.ticket_id, t.url AS ticket_url,
           e.text AS granite_explanation"""

_JOINS = """
    LEFT JOIN clean.kev k ON k.cve_id = m.cve_id
    LEFT JOIN vulnerabilities v ON v.cve_id = m.cve_id
    LEFT JOIN weakness_types w
      ON w.cwe_id = nullif(trim(split_part(coalesce(v.cwe_ids, ''), ';', 1)), '')
    LEFT JOIN app.queue_status qs ON qs.sbom_id = $sbom_id AND qs.cve_id = m.cve_id
    LEFT JOIN app.tickets t ON t.sbom_id = $sbom_id AND t.cve_id = m.cve_id
    LEFT JOIN app.explanations e ON e.cve_id = m.cve_id"""

_RANKED = """
ranked AS (
    SELECT row_number() OVER (
               ORDER BY on_kev DESC, score DESC NULLS LAST, cvss_raw DESC NULLS LAST, cve_id
           ) AS rank,
           row_number() OVER (ORDER BY cvss_raw DESC NULLS LAST, cve_id) AS cvss_rank,
           *
    FROM joined
)
SELECT * FROM ranked ORDER BY rank"""

# Placeholder ranking (no predictions.parquet): KEV first, then the EPSS percentile of the
# most recent signal, then CVSS, then CVE id for a stable order.
_PLACEHOLDER_SQL = f"""
WITH {_MATCHED}, {_SIGNALS},
joined AS (
    SELECT m.cve_id, m.components, m.match_methods, m.version_status, m.shown, m.assets,
           s.epss_pct AS score,
           s.epss,
           coalesce(s.exploit_code, false) AS exploit_code,
           {_COMMON}
    FROM matched m
    LEFT JOIN scored s ON s.cve_id = m.cve_id
    {_JOINS}
),
{_RANKED}
"""


def _model_sql(predictions: str) -> str:
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
    SELECT m.cve_id, m.components, m.match_methods, m.version_status, m.shown, m.assets,
           p.score, p.score_pct, p.p_exploit, p.model_pct, p.confidence, p.basis, p.as_of,
           p.similarity_used, p.reasons, p.signal,
           s.epss,
           coalesce(s.exploit_code, p.any_exploit_code = 1, false) AS exploit_code,
           c.granite_verdict, c.granite_reason,
           {_COMMON}
    FROM matched m
    LEFT JOIN {predictions} p ON p.cve_id = m.cve_id
    LEFT JOIN scored s ON s.cve_id = m.cve_id
    LEFT JOIN checks c ON c.cve_id = m.cve_id
    {_JOINS}
),
{_RANKED}
"""


# --- predictions and freshness ---------------------------------------------------------------


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
            f"SELECT safety_raw FROM {predictions} "
            "WHERE safety_raw IS NOT NULL AND confidence <> 'exploited' ORDER BY 1"
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
    """Flag scores describing an old month. Being on KEV doesn't go stale."""
    for r in rows:
        end = month_end(r.get("as_of"))
        old = end is not None and (today - end).days > config.SCORE_STALE_DAYS
        r["stale"] = old and not r.get("on_kev")


# --- presentation (pure, unit-tested) --------------------------------------------------------


def severity(cvss: float | None) -> str:
    """NVD's CVSS v3 bands."""
    if cvss is None or cvss <= 0:
        return "none"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


_VENDOR_NAMES: dict[int, dict[str, str]] = {}  # per connection


VENDOR_NAMES_SQL = """
    SELECT vendor_key, mode(vendor) FROM clean.kev
    WHERE vendor_key IS NOT NULL AND vendor IS NOT NULL GROUP BY 1
"""


def vendor_names(con) -> dict[str, str]:
    """Vendor key -> the display name CISA's KEV list uses ("paloaltonetworks" -> "Palo
    Alto Networks"). KEV vendor keys use the same normalisation as CPE vendor keys.
    Loaded once."""
    key = id(con)
    if key not in _VENDOR_NAMES:
        try:
            rows = con.execute(VENDOR_NAMES_SQL).fetchall()
        except Exception:  # noqa: BLE001 - no KEV table: fall back to tidied keys
            rows = []
        _VENDOR_NAMES[key] = {k: v for k, v in rows if k and v}
    return _VENDOR_NAMES[key]


def display_vendor(vendor: str | None, names: dict[str, str]) -> str | None:
    if not vendor:
        return None
    key = re.sub(r"[^a-z0-9]", "", vendor.lower())
    if key in names:
        return names[key]
    if vendor.islower() or "_" in vendor:  # a CPE id such as "palo_alto" or "apache"
        return " ".join(w.capitalize() for w in re.split(r"[_\s]+", vendor) if w)
    return vendor


def initials(name: str | None) -> str | None:
    """Two letters for the avatar: first letters of two words, or of a CamelCase word
    ("WatchGuard" -> "WG"), else its first two letters."""
    if not name:
        return None
    words = [w for w in re.split(r"[\s\-_/.]+", name) if w]
    if len(words) >= 2:
        return (words[0][0] + words[1][0]).upper()
    capitals = re.findall(r"[A-Z]", words[0][1:])
    if capitals:
        return (words[0][0] + capitals[0]).upper()
    return words[0][:2].upper()


def plain_explanation(row: dict) -> str:
    """1-2 sentences under 200 characters from NVD and CISA KEV facts."""
    description = " ".join((row.get("description") or "").split())
    first = re.split(r"(?<=[.!?])\s+", description, maxsplit=1)[0] if description else ""
    if row.get("on_kev"):
        status = "CISA confirms attackers are using it"
        status += ", including in ransomware." if row.get("known_ransomware") else "."
    elif row.get("exploit_code"):
        status = "Public attack code exists, but no confirmed attacks yet."
    else:
        status = "No public attack code or confirmed attacks yet."
    room = 199 - len(status) - 1
    if len(first) > room:
        first = first[: max(0, room - 1)].rsplit(" ", 1)[0].rstrip(",;:") + "…"
    return f"{first} {status}".strip()


def present_row(r: dict, names: dict[str, str]) -> dict:
    """The raw SQL row as the frontend reads it."""
    shown = r.pop("shown") or {}
    component = shown.get("name") or (r["components"][0] if r["components"] else r["cve_id"])
    vendor = display_vendor(shown.get("vendor"), names)
    assets = int(r.pop("assets") or 1)
    cvss = r.pop("cvss_raw")
    r["component"] = component
    r["cvss_score"] = round(float(cvss), 1) if cvss is not None else 0.0
    r["severity"] = severity(cvss)
    r["vendor_initials"] = initials(vendor or component)
    r["subtitle"] = " · ".join(
        [x for x in (vendor, component) if x] + [f"{assets} SBOM asset{'s' if assets != 1 else ''}"]
    )
    ticket_id, ticket_url = r.pop("ticket_id"), r.pop("ticket_url")
    r["ticket"] = {"id": ticket_id, "url": ticket_url} if ticket_id else None
    granite = r.pop("granite_explanation")
    r["explanation"] = granite or plain_explanation(r)
    r["explanation_source"] = "granite" if granite else "nvd"
    r["reasons"] = [dict(x) for x in (r.get("reasons") or [])]
    r["reasons_are_sample"] = not r["reasons"]
    r.setdefault("signal", None)
    if r.get("score") is None and r.get("on_kev"):
        r["score"] = 1.0
    return r


def counts(rows: list[dict]) -> dict:
    return {
        "open": len(rows),
        "critical": sum(1 for r in rows if r["severity"] == "critical"),
        "not_in_linear": sum(1 for r in rows if r["ticket"] is None),
        "warning_signs": sum(1 for r in rows if r.get("signal") is not None),
    }


# --- the queue -------------------------------------------------------------------------------


def _rows(cur) -> list[dict]:
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


def full_queue(
    con, sbom_id: str, live: bool | None = None, today: date | None = None, fetch=None
) -> dict:
    """Every row of the SBOM's queue, ranked and presented, with counts."""
    predictions = predictions_source()
    params = {"sbom_id": sbom_id}
    if predictions is None:
        rows = _rows(con.execute(_PLACEHOLDER_SQL, params))
        out = {"ranking": "epss_placeholder", "scores": {}}
    else:
        live = config.EPSS_LIVE if live is None else live
        meta = predictions_meta()
        rows = _rows(con.execute(_model_sql(predictions), params))
        ranking = "model"
        if live:
            rows = _rerank_live(con, rows, predictions, float(meta.get("alpha", 1.0)), fetch)
            ranking = "model_live_epss"
        out = {"ranking": ranking, "scores": meta}
    names = vendor_names(con)
    rows = [present_row(r, names) for r in rows]
    if predictions is not None:
        mark_stale(rows, today or date.today())
    if config.GRANITE_EXPLANATIONS and rows:
        from backend.services.granite_explain import ensure_explanations

        ensure_explanations(con, rows[: config.GRANITE_EXPLAIN_TOP])
    return {"sbom_id": sbom_id, "total": len(rows), "counts": counts(rows), "items": rows, **out}


# The full queue takes a few seconds for a large SBOM (every match is joined and scored),
# and the Fix first page asks for it again on every search. It is kept per SBOM for a few
# minutes; every write (status, ticket, upload, delete) calls `forget`.
# Keyed by SBOM id alone: each request gets its own cursor on the one database, so the
# connection can't be part of the key (tests clear it with forget()).
_QUEUE_CACHE: dict[str, tuple[float, dict]] = {}
QUEUE_CACHE_SECONDS = 300


def forget(sbom_id: str | None = None) -> None:
    """Drop the cached queue of one SBOM (or of all)."""
    if sbom_id is None:
        _QUEUE_CACHE.clear()
    else:
        _QUEUE_CACHE.pop(sbom_id, None)


def cached_queue(con, sbom_id: str) -> dict:
    """full_queue with the default (configured) scoring, cached per SBOM."""
    now = time.monotonic()
    hit = _QUEUE_CACHE.get(sbom_id)
    if hit is None or now - hit[0] > QUEUE_CACHE_SECONDS:
        hit = (now, full_queue(con, sbom_id))
        _QUEUE_CACHE[sbom_id] = hit
    return hit[1]


VIEWS = ("all", "critical", "not_in_linear", "warning_signs")
SORTS = ("rank", "cvss_desc", "cvss_asc")


def filter_rows(
    rows: list[dict], q: str | None = None, view: str = "all", sort: str = "rank"
) -> list[dict]:
    """The rows a Fix first view shows: search on CVE id and component names, a filter
    chip, and the sort (CVSS ties keep the model's order). Never changes `rows`."""
    needle = (q or "").strip().lower()
    keep = {
        "all": lambda r: True,
        "critical": lambda r: r["severity"] == "critical",
        "not_in_linear": lambda r: r["ticket"] is None,
        "warning_signs": lambda r: r.get("signal") is not None,
    }[view]
    out = [
        r
        for r in rows
        if keep(r)
        and (
            not needle
            or needle in r["cve_id"].lower()
            or any(needle in c.lower() for c in [r["component"], *r["components"]])
        )
    ]
    if sort != "rank":
        sign = -1 if sort == "cvss_desc" else 1
        out.sort(key=lambda r: (sign * r["cvss_score"], r["rank"]))
    return out


def build_queue(
    con,
    sbom_id: str,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    q: str | None = None,
    view: str = "all",
    sort: str = "rank",
    live: bool | None = None,
    today: date | None = None,
    fetch=None,
) -> dict:
    """One page of the SBOM's Fix-First queue after search, filter and sort. `total` and
    `counts` cover the whole queue; `matched` is the number of rows the view selects.
    `live`, `today` and `fetch` (the FIRST call) are for tests and skip the cache."""
    if live is None and today is None and fetch is None:
        queue = cached_queue(con, sbom_id)
    else:
        queue = full_queue(con, sbom_id, live=live, today=today, fetch=fetch)
    rows = filter_rows(queue["items"], q, view, sort)
    return {**queue, "matched": len(rows), "items": rows[offset : offset + limit]}


STATUSES = ("to_do", "in_progress", "done")


def in_queue(con, sbom_id: str, cve_id: str) -> bool:
    return (
        con.execute(
            "SELECT 1 FROM app.matches WHERE sbom_id = ? AND cve_id = ? LIMIT 1", [sbom_id, cve_id]
        ).fetchone()
        is not None
    )


def set_status(con, sbom_id: str, cve_id: str, status: str) -> None:
    from datetime import UTC, datetime

    con.execute(
        "INSERT OR REPLACE INTO app.queue_status VALUES (?, ?, ?, ?)",
        [sbom_id, cve_id, status, datetime.now(UTC).replace(tzinfo=None)],
    )


def queue_row(con, sbom_id: str, cve_id: str) -> dict | None:
    """One presented row (with its rank in the full queue), or None if not in the queue."""
    for row in cached_queue(con, sbom_id)["items"]:
        if row["cve_id"] == cve_id:
            return row
    return None


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
            -(r["cvss_raw"] if r["cvss_raw"] is not None else -1.0),
            r["cve_id"],
        )

    rows.sort(key=key)
    for i, r in enumerate(rows, 1):
        r["rank"] = i
    return rows
