"""Push a queue row to Linear as an issue (GraphQL API). The API key stays on the backend
(LINEAR_API_KEY in backend/.env); the team is LINEAR_TEAM_KEY (for example "SHE").
Plain functions; no FastAPI.
"""

from datetime import UTC, datetime

import httpx

from backend.core import config

API_URL = "https://api.linear.app/graphql"
TIMEOUT_S = 15.0
NOT_SET_UP = "Linear isn't set up yet. Add LINEAR_API_KEY and LINEAR_TEAM_KEY to the backend."
NO_RESPONSE = "Linear didn't respond. Try again."

TEAM_QUERY = """
query Team($key: String!) {
  teams(filter: { key: { eq: $key } }) { nodes { id key } }
}"""
CREATE_ISSUE = """
mutation Create($input: IssueCreateInput!) {
  issueCreate(input: $input) { success issue { identifier url } }
}"""


class LinearError(RuntimeError):
    """A message that is safe to show to the user (HTTP 502)."""


def _post(query: str, variables: dict, post=None) -> dict:
    post = post or (
        lambda payload: httpx.post(
            API_URL,
            json=payload,
            headers={"Authorization": config.LINEAR_API_KEY, "Content-Type": "application/json"},
            timeout=TIMEOUT_S,
        )
    )
    try:
        response = post({"query": query, "variables": variables})
        response.raise_for_status()
        body = response.json()
    except Exception as error:
        raise LinearError(NO_RESPONSE) from error
    if body.get("errors"):
        raise LinearError(NO_RESPONSE)
    return body["data"]


def issue_text(row: dict) -> tuple[str, str]:
    """Title `<cve_id> · <component>` and a Markdown body with the facts."""
    title = f"{row['cve_id']} · {row['component']}"
    reasons = (
        "\n".join(f"- {r['label']} ({r['value']:+.2f})" for r in row.get("reasons") or [])
        or "- (no model reasons)"
    )
    body = (
        f"{row['explanation']}\n\n"
        f"**Fix-first rank:** #{row['rank']}  \n"
        f"**CVSS:** {row['cvss_score']} ({row['severity']})  \n"
        f"**On CISA KEV:** {'yes, since ' + str(row['kev_date_added']) if row.get('on_kev') else 'no'}\n\n"
        f"**Why it ranks here**\n{reasons}\n\n"
        f"NVD: https://nvd.nist.gov/vuln/detail/{row['cve_id']}"
    )
    return title, body


def existing_ticket(con, sbom_id: str, cve_id: str) -> dict | None:
    row = con.execute(
        "SELECT ticket_id, url FROM app.tickets WHERE sbom_id = ? AND cve_id = ?", [sbom_id, cve_id]
    ).fetchone()
    return {"id": row[0], "url": row[1]} if row else None


def create_ticket(con, sbom_id: str, row: dict, post=None) -> dict:
    """Create the Linear issue for a queue row and remember it. `post` is for tests."""
    if not config.LINEAR_API_KEY or not config.LINEAR_TEAM_KEY:
        raise LinearError(NOT_SET_UP)
    teams = _post(TEAM_QUERY, {"key": config.LINEAR_TEAM_KEY}, post)["teams"]["nodes"]
    if not teams:
        raise LinearError(f"Linear has no team with key {config.LINEAR_TEAM_KEY}.")
    title, description = issue_text(row)
    created = _post(
        CREATE_ISSUE,
        {"input": {"teamId": teams[0]["id"], "title": title, "description": description}},
        post,
    )["issueCreate"]
    if not created.get("success") or not created.get("issue"):
        raise LinearError(NO_RESPONSE)
    ticket = {"id": created["issue"]["identifier"], "url": created["issue"]["url"]}
    con.execute(
        "INSERT OR REPLACE INTO app.tickets VALUES (?, ?, ?, ?, ?)",
        [
            sbom_id,
            row["cve_id"],
            ticket["id"],
            ticket["url"],
            datetime.now(UTC).replace(tzinfo=None),
        ],
    )
    return ticket
