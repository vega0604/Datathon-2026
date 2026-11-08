"""Today's EPSS from FIRST, to refresh the queue's safety half (opt-in: EPSS_LIVE).

The stored scores use EPSS as of each vulnerability's snapshot month. With EPSS_LIVE on,
the queue asks FIRST's public API (api.first.org) for today's EPSS of the matched CVEs
only (their IDs are public), and re-scores each one:

    safety_live = live EPSS percentile + 1.0 x exploit code (as stored)
    score_live  = alpha x model_pct + (1 - alpha) x pct of safety_live among all stored
                  safety scores

Any network problem leaves the stored scores in place. Plain functions; no FastAPI.
"""

import bisect
import logging

import httpx

FIRST_URL = "https://api.first.org/data/v1/epss"
BATCH = 100
TIMEOUT_S = 10.0

log = logging.getLogger(__name__)


def fetch_epss(cves: list[str], get=None) -> dict[str, dict]:
    """cve_id -> {"epss", "percentile", "date"} for the CVEs FIRST knows. `get` is for tests."""
    get = get or (lambda params: httpx.get(FIRST_URL, params=params, timeout=TIMEOUT_S))
    out: dict[str, dict] = {}
    for i in range(0, len(cves), BATCH):
        batch = cves[i : i + BATCH]
        try:
            response = get({"cve": ",".join(batch)})
            response.raise_for_status()
            rows = response.json().get("data", [])
        except Exception as error:  # noqa: BLE001 - offline or API down: keep stored scores
            log.warning("live EPSS unavailable: %s", error)
            break
        for row in rows:
            out[row["cve"]] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
                "date": row.get("date"),
            }
    return out


def percentile_in(sorted_values: list[float], value: float) -> float:
    """Share of the stored values at or below `value` (matches rank(pct, method='max'))."""
    if not sorted_values:
        return 0.0
    return bisect.bisect_right(sorted_values, value) / len(sorted_values)


def rescore(item: dict, live: dict, alpha: float, safety_sorted: list[float]) -> dict:
    """Live-EPSS fields for one queue item; unchanged when it is on KEV or has no model part."""
    fields = {"epss_live": live["epss"], "epss_live_pct": live["percentile"],
              "epss_live_date": live["date"], "score_live": None}  # fmt: skip
    if item.get("on_kev") or item.get("model_pct") is None:
        return fields
    safety = live["percentile"] + 1.0 * (1 if item.get("exploit_code") else 0)
    fields["score_live"] = alpha * item["model_pct"] + (1 - alpha) * percentile_in(
        safety_sorted, safety
    )
    return fields
