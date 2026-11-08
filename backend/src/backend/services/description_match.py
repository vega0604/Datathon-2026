"""Match SBOM components to vulnerabilities NIST hasn't analysed yet, by their description.

NIST has not reviewed most 2026 vulnerabilities, so they have no product list and the
CPE/purl matcher can't see them. Every vulnerability has a description, so a component
whose product name appears there (as a whole word) is a candidate match:

- only vulnerabilities with no vulnerable product rows are searched (the CPE matcher
  covers the rest), and rejected entries are skipped;
- the name must be at least 4 characters and not a generic word ("core", "server", ...);
- the name must appear in the first 12 words, where descriptions name the vulnerable
  product, and not only as the host of an add-on ("a Jenkins plugin");
- descriptions about plugins, themes, extensions, add-ons or integrations are skipped:
  the flaw is in the add-on, not in the platform the SBOM lists;
- when the component has a vendor, the vendor must appear too, unless the name is long
  and distinctive (at least 8 characters).

Matches are stored with method 'description' and version_status 'unverified': the
description rarely gives a version range we can check. Granite can confirm them
(services/match_verify.py). Plain functions; no FastAPI.
"""

import re

import pandas as pd

MIN_TERM = 4
DISTINCTIVE_TERM = 8
GENERIC = {
    "core", "common", "utils", "util", "server", "client", "plugin", "library", "framework",
    "java", "python", "node", "http", "https", "json", "test", "tools", "data", "base",
    "service", "system", "admin", "user", "file", "files", "page", "web", "site", "module",
    "manager", "portal", "theme", "form", "forms", "api", "sdk", "cli", "app", "apps",
}  # fmt: skip


def normalise(text: str | None) -> str | None:
    """Lower case; CPE-style underscores become spaces ("http_server" -> "http server")."""
    if text is None:
        return None
    text = re.sub(r"\s+", " ", text.lower().replace("_", " ")).strip()
    return text or None


def usable(term: str | None) -> bool:
    return term is not None and len(term) >= MIN_TERM and term not in GENERIC


# Hyphens, underscores and inner dots belong to a name: "django-haystack" is not "django",
# "openssl_encrypt" is not "openssl", "mongodb.py" is not "mongodb".
_BEFORE = r"(?<![a-z0-9_\-./])"
_AFTER = r"(?![a-z0-9_\-/]|\.[a-z0-9])"


def mentions(term: str, text: str):
    return re.finditer(rf"{_BEFORE}{re.escape(term)}{_AFTER}", text)


def whole_word(term: str, text: str) -> bool:
    return next(mentions(term, text), None) is not None


# "The Foo plugin for WordPress", "a Chrome extension", "Jenkins add on": the flaw is in the
# add-on, not in the component the description names.
ADDON = r"(?:plugins?|themes?|extensions?|add ?ons?|addons?|modules?|integrations?|apps?|widgets?)"
# "MongoDB C# Driver", "OpenSSL bindings": a separate product that talks to the component.
CLIENT_LIBRARY = r"(?:drivers?|librar(?:y|ies)|sdks?|bindings?|wrappers?|connectors?|adapters?)"


def names_the_product(term: str, text: str, within: int | None = None) -> bool:
    """True if some whole-word mention of `term` (starting before character `within`)
    isn't only the host of an add-on or the target of a client library."""
    for found in mentions(term, text):
        if within is not None and found.start() >= within:
            break
        before = text[max(0, found.start() - 40) : found.start()]
        after = text[found.end() : found.end() + 25]
        hosted = (
            re.search(rf"\b(?:{ADDON}\s+)?(?:for|in|on)\s+(?:the\s+)?$", before)
            if re.search(rf"\b{ADDON}\s+(?:for|in|on)\s+(?:the\s+)?$", before)
            else re.search(r"\bfor\s+(?:the\s+)?$", before)  # "Maps for WordPress"
        ) or re.match(rf"\s+(?:\S+\s+)?(?:{ADDON}|{CLIENT_LIBRARY})\b", after)
        if not hosted:
            return True
    return False


HEAD_WORDS = 12  # descriptions name the vulnerable product first
ADDON_ANYWHERE = re.compile(r"\b(?:plugins?|themes?|extensions?|add ?ons?|addons?|integrations?)\b")


def accept(term: str, vendor: str | None, description: str) -> bool:
    """The rule for one (component term, description) pair, both normalised."""
    head = " ".join(description.split()[:HEAD_WORDS])
    if ADDON_ANYWHERE.search(description) or not names_the_product(
        term, description, within=len(head)
    ):
        return False
    # Short or multi-word names ("nginx", "http server") need the vendor named too; a long
    # single word ("keycloakx") is distinctive enough alone.
    distinctive = len(term) >= DISTINCTIVE_TERM and " " not in term
    if vendor and vendor not in term and not distinctive:
        return whole_word(vendor, description)
    return True


def component_terms(con, sbom_id: str) -> pd.DataFrame:
    """component_id, term (normalised product or name), vendor (normalised)."""
    rows = con.execute(
        "SELECT component_id, coalesce(product, name) AS term, coalesce(vendor, group_name) "
        "AS vendor FROM app.components WHERE sbom_id = ?",
        [sbom_id],
    ).fetchall()
    out = [
        (cid, normalise(term), normalise(vendor))
        for cid, term, vendor in rows
        if usable(normalise(term))
    ]
    return pd.DataFrame(out, columns=["component_id", "term", "vendor"])


CANDIDATES_SQL = """
    WITH unanalysed AS (
        SELECT v.cve_id, regexp_replace(lower(v.description), '\\s+', ' ', 'g') AS d
        FROM vulnerabilities AS v
        WHERE v.description IS NOT NULL
          AND NOT starts_with(v.description, 'Rejected reason')
          AND NOT starts_with(v.description, '** REJECT')
          AND NOT EXISTS (
              SELECT 1 FROM clean.affected_products AS a
              WHERE a.cve_id = v.cve_id AND a.vulnerable = 'Y'
          )
    )
    SELECT t.component_id, t.term, t.vendor, u.cve_id, u.d
    FROM _terms AS t
    JOIN unanalysed AS u ON contains(u.d, t.term)
"""


def match_descriptions(con, sbom_id: str) -> int:
    """Add description matches to app.matches (not overriding CPE/purl matches). Returns
    the number of (component, cve) pairs added."""
    terms = component_terms(con, sbom_id)
    if terms.empty:
        return 0
    cur = con.cursor()
    try:
        cur.register("_terms", terms)
        candidates = cur.execute(CANDIDATES_SQL).fetchall()
    finally:
        cur.close()
    existing = {
        (c, v)
        for c, v in con.execute(
            "SELECT component_id, cve_id FROM app.matches WHERE sbom_id = ?", [sbom_id]
        ).fetchall()
    }
    new = sorted(
        {
            (cid, cve)
            for cid, term, vendor, cve, desc in candidates
            if (cid, cve) not in existing and accept(term, vendor, desc)
        }
    )
    if not new:
        return 0
    df = pd.DataFrame(
        {"sbom_id": sbom_id, "component_id": [c for c, _ in new], "cve_id": [v for _, v in new],
         "method": "description", "version_status": "unverified"}
    )  # fmt: skip
    con.register("_desc_matches", df)
    try:
        con.execute("INSERT INTO app.matches SELECT * FROM _desc_matches")
    finally:
        con.unregister("_desc_matches")
    return len(df)
