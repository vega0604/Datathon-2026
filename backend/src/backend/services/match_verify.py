"""Let Granite on watsonx confirm description-only matches (opt-in: GRANITE_MATCH_CHECK).

For one SBOM, the highest-scored description matches (at most MAX_MATCH_CHECKS, to bound
token use) go through the SHE-38/39 match check. A "no" removes the match; "yes" and
"unknown" keep it, and every verdict is stored in app.match_checks for the queue to show.
Any watsonx problem (missing credentials, token budget, timeout) stops the checks and
leaves the remaining matches unverified. Plain functions; no FastAPI.
"""

import logging

from backend.core import config
from backend.services.match_check import Component, check_match

log = logging.getLogger(__name__)


def to_check_sql(predictions: str | None) -> str:
    order = "p.score DESC NULLS LAST, " if predictions else ""
    join = f"LEFT JOIN {predictions} AS p ON p.cve_id = m.cve_id" if predictions else ""
    return f"""
        SELECT m.component_id, m.cve_id, c.name, coalesce(c.vendor, c.group_name), c.version,
               v.description
        FROM app.matches AS m
        JOIN app.components AS c ON c.sbom_id = m.sbom_id AND c.component_id = m.component_id
        JOIN vulnerabilities AS v ON v.cve_id = m.cve_id
        {join}
        WHERE m.sbom_id = ? AND m.method = 'description'
          AND NOT EXISTS (
              SELECT 1 FROM app.match_checks AS x
              WHERE x.sbom_id = m.sbom_id AND x.component_id = m.component_id
                AND x.cve_id = m.cve_id
          )
        ORDER BY {order}m.cve_id, m.component_id
        LIMIT ?
    """


def verify_description_matches(
    con, sbom_id: str, client=None, predictions: str | None = None, limit: int | None = None
) -> dict:
    """Check up to `limit` description matches with Granite; returns counts per verdict."""
    limit = config.MAX_MATCH_CHECKS if limit is None else limit
    if client is None:
        from backend.services.watsonx import WatsonxClient

        client = WatsonxClient(purpose="sbom_match")
    rows = con.execute(to_check_sql(predictions), [sbom_id, limit]).fetchall()
    counts = {"yes": 0, "no": 0, "unknown": 0, "errors": 0, "stopped": False}
    for component_id, cve, name, vendor, version, description in rows:
        try:
            verdict = check_match(client, description, Component(name, vendor, version))
        except Exception as error:  # noqa: BLE001 - watsonx unavailable: stop, keep matches
            log.warning("Granite match check stopped: %s", error)
            counts["stopped"] = True
            break
        con.execute(
            "INSERT OR REPLACE INTO app.match_checks VALUES (?, ?, ?, ?, ?, ?, ?)",
            [sbom_id, component_id, cve, verdict.affected, verdict.confidence,
             verdict.reason, verdict.error],
        )  # fmt: skip
        counts["errors" if verdict.error else verdict.affected] += 1
        if verdict.affected == "no" and not verdict.error:
            con.execute(
                "DELETE FROM app.matches WHERE sbom_id = ? AND component_id = ? AND cve_id = ?",
                [sbom_id, component_id, cve],
            )
    return counts
