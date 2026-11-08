"""Granite writes the "In plain words" explanation for the top rows of a queue (opt-in:
GRANITE_EXPLANATIONS). Each CVE is explained once and cached in app.explanations; every
other row keeps the NVD/KEV template. Any watsonx problem stops quietly, leaving the
template in place. Plain functions; no FastAPI.
"""

import logging
from datetime import UTC, datetime

log = logging.getLogger(__name__)

MAX_CHARS = 200
MAX_TOKENS = 90
SYSTEM = (
    "You explain software vulnerabilities to non-experts. Using only the facts given, write "
    "1 or 2 short sentences (under 200 characters in total) saying what an attacker could "
    "do and whether attacks are confirmed. No jargon, no CVE ids, no Markdown."
)


def prompt(row: dict) -> list[dict]:
    facts = [
        f"Software: {row.get('component')}",
        f"NVD description: {(row.get('description') or '')[:900]}",
        f"On CISA's Known Exploited Vulnerabilities list: {'yes' if row.get('on_kev') else 'no'}",
        f"Used in ransomware: {'yes' if row.get('known_ransomware') else 'not known'}",
        f"Public exploit code: {'yes' if row.get('exploit_code') else 'not seen'}",
    ]
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "\n".join(facts)}]


def tidy(text: str) -> str | None:
    text = " ".join(text.replace("*", "").replace("`", "").split()).strip('" ')
    if not text:
        return None
    if len(text) > MAX_CHARS:
        cut = text[:MAX_CHARS]
        end = max(cut.rfind(". "), cut.rfind("! "))
        text = cut[: end + 1] if end > 40 else cut[: MAX_CHARS - 1].rsplit(" ", 1)[0] + "…"
    return text


def ensure_explanations(con, rows: list[dict], client=None) -> int:
    """Fill Granite explanations for `rows` that don't have one yet; updates the rows in
    place and returns how many were written."""
    todo = [r for r in rows if r.get("explanation_source") != "granite"]
    if not todo:
        return 0
    if client is None:
        from backend.services.watsonx import WatsonxClient

        client = WatsonxClient(purpose="explanation")
    written = 0
    for row in todo:
        try:
            text, _ = client.chat(prompt(row), max_tokens=MAX_TOKENS)
        except Exception as error:  # noqa: BLE001 - watsonx unavailable: keep the template
            log.warning("Granite explanations stopped: %s", error)
            break
        text = tidy(text)
        if not text:
            continue
        con.execute(
            "INSERT OR REPLACE INTO app.explanations VALUES (?, ?, ?)",
            [row["cve_id"], text, datetime.now(UTC).replace(tzinfo=None)],
        )
        row["explanation"], row["explanation_source"] = text, "granite"
        written += 1
    return written
