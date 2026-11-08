"""SHE-56: up to 3 plain-language reasons per vulnerability, from SHAP.

    reasons = top_reasons(booster, X, raw_df, k=3, cwe_names=load_cwe_names(con))

shap.TreeExplainer gives each feature's contribution to a row's score. Contributions are
summed within a template family (all exploit flags make one reason, all CVSS fields
another), the families with the largest positive totals are taken, and each is written
from the row's real values. A family that can't be stated truthfully (for example an
exploit-flag contribution when no flag is set) is skipped, never invented, so a row can
get fewer than k reasons. days_to_cutoff is never a reason: it isn't meaningful to users.
"""

import math
import re

import numpy as np
import pandas as pd

from backend.modeling.features import CVSS3_METRICS, KEYWORDS

EXPLOIT_FLAGS = {
    "metasploit": "Metasploit",
    "nuclei": "Nuclei",
    "exploitdb": "Exploit-DB",
    "poc_github": "GitHub proof of concept",
}
KEYWORD_PHRASES = {
    "kw_unauthenticated": "Description mentions unauthenticated access",
    "kw_remote_code_execution": "Description mentions remote code execution",
    "kw_command_injection": "Description mentions command injection",
    "kw_pre_auth": "Description mentions pre-authentication access",
    "kw_default_config": "Description says the default configuration is affected",
    "kw_auth_bypass": "Description mentions an authentication bypass",
    "kw_path_traversal": "Description mentions path traversal",
    "kw_deserialization": "Description mentions unsafe deserialization",
    "kw_privilege_escalation": "Description mentions privilege escalation",
    "kw_sql_injection": "Description mentions SQL injection",
    "kw_exploited": "Description says it has been exploited",
}
SKIP = {"days_to_cutoff"}
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def family(feature: str) -> str | None:
    """The reason template a feature belongs to (None: never a reason)."""
    if feature in SKIP:
        return None
    if feature in EXPLOIT_FLAGS or feature == "any_exploit_code":
        return "exploit"
    if feature == "epss_pct":
        return "epss"
    if feature.startswith("assigner_"):
        return "assigner"
    if feature.startswith("kev_sim_"):
        return "similarity"
    if feature in KEYWORDS:
        return feature
    if feature in CVSS3_METRICS or feature in ("cvss3_score", "cvss4_score"):
        return "cvss"
    if feature in ("cwe_primary", "n_cwes"):
        return "cwe"
    return None


def present(value) -> bool:
    return (
        value is not None
        and not (isinstance(value, float) and math.isnan(value))
        and not (value is pd.NA)
    )


def cvss_sentence(row) -> str | None:
    vector = {
        "NETWORK": "Reachable over the network",
        "ADJACENT_NETWORK": "Reachable from an adjacent network",
    }.get(row.get("attack_vector"))
    needs = []
    if row.get("privileges_required") == "NONE":
        needs.append("no privileges needed")
    if row.get("user_interaction") == "NONE":
        needs.append("no user interaction")
    if row.get("attack_complexity") == "LOW":
        needs.append("low attack complexity")
    score = row.get("cvss3_score")
    suffix = f" (CVSS {score:.1f})" if present(score) else ""
    if vector:
        return f"{vector}{' with ' + ' and '.join(needs) if needs else ''}{suffix}"
    if needs:
        return f"Exploitable with {' and '.join(needs)}{suffix}"
    if present(score) and score >= 7:
        return f"High severity (CVSS {score:.1f})"
    cvss4 = row.get("cvss4_score")
    if present(cvss4) and cvss4 >= 7:
        return f"High severity (CVSS 4 score {cvss4:.1f})"
    return None


def render(name: str, row, cwe_names: dict[str, str] | None = None) -> str | None:
    """One reason sentence from the row's real values, or None if it can't be stated."""
    if name == "exploit":
        flags = [label for column, label in EXPLOIT_FLAGS.items() if row.get(column) == 1]
        return f"Public exploit code exists ({', '.join(flags)})" if flags else None
    if name == "epss":
        pct = row.get("epss_pct")
        if not present(pct):
            return None
        return f"EPSS is higher than {math.floor(pct * 100)}% of vulnerabilities that month"
    if name == "assigner":
        n = row.get("assigner_kev_prior")
        if not present(n) or n <= 0:
            return None
        who = row.get("assigner")
        who = "Its assigning organisation" if not present(who) or UUID.match(str(who)) else who
        noun = "vulnerability" if int(n) == 1 else "vulnerabilities"
        return f"{who} has had {int(n):,} {noun} added to KEV before"
    if name == "similarity":
        sim = row.get("kev_sim_max")
        if not present(sim):
            return None
        return (
            f"Description closely resembles known-exploited vulnerabilities (similarity {sim:.2f})"
        )
    if name in KEYWORD_PHRASES:
        return KEYWORD_PHRASES[name] if row.get(name) == 1 else None
    if name == "cvss":
        return cvss_sentence(row)
    if name == "cwe":
        cwe = row.get("cwe_primary")
        if not present(cwe) or cwe in ("unknown", "other"):
            return None
        return f"Weakness type: {(cwe_names or {}).get(cwe) or cwe}"
    return None


def reasons_from_contributions(
    contributions: np.ndarray,
    feature_names: list[str],
    raw: pd.DataFrame,
    k: int = 3,
    cwe_names: dict[str, str] | None = None,
) -> list[list[str]]:
    """contributions: (rows, features) SHAP values aligned with raw's rows."""
    families = [family(f) for f in feature_names]
    names = sorted({f for f in families if f})
    index = {name: i for i, name in enumerate(names)}
    totals = np.zeros((contributions.shape[0], len(names)))
    for j, fam in enumerate(families):
        if fam:
            totals[:, index[fam]] += contributions[:, j]
    out = []
    records = raw.to_dict("records")
    for i, row in enumerate(records):
        order = np.argsort(-totals[i], kind="stable")
        reasons = []
        for j in order:
            if totals[i, j] <= 0 or len(reasons) == k:
                break
            sentence = render(names[j], row, cwe_names)
            if sentence:
                reasons.append(sentence)
        out.append(reasons)
    return out


# --- short reason bars for the frontend panel ---------------------------------------------

LABEL_MAX = 45
# The panel has three icons: exploit (code), exposure (shield), vendor (building).
KIND = {"exploit": "exploit", "epss": "exploit", "assigner": "vendor"}  # default: exposure
SHORT_KEYWORDS = {
    "kw_unauthenticated": "Mentions unauthenticated access",
    "kw_remote_code_execution": "Mentions remote code execution",
    "kw_command_injection": "Mentions command injection",
    "kw_pre_auth": "Mentions pre-authentication access",
    "kw_default_config": "Affects the default configuration",
    "kw_auth_bypass": "Mentions an authentication bypass",
    "kw_path_traversal": "Mentions path traversal",
    "kw_deserialization": "Mentions unsafe deserialization",
    "kw_privilege_escalation": "Mentions privilege escalation",
    "kw_sql_injection": "Mentions SQL injection",
    "kw_exploited": "Says it has been exploited",
}
SHORT_FLAGS = {"metasploit": "Metasploit", "nuclei": "Nuclei", "exploitdb": "Exploit-DB",
               "poc_github": "GitHub PoC"}  # fmt: skip


def clip(text: str, limit: int = LABEL_MAX) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def organisation(assigner, names: dict[str, str] | None = None) -> str:
    """A readable organisation name from an assigner e-mail ("psirt@fortinet.com" ->
    "Fortinet"). `names` maps vendor keys to CISA display names ("paloaltonetworks" ->
    "Palo Alto Networks")."""
    if not present(assigner) or UUID.match(str(assigner)) or "@" not in str(assigner):
        return "Its vendor"
    domain = str(assigner).split("@", 1)[1].lower().split(".")
    name = domain[-2] if len(domain) >= 2 else domain[0]
    special = {"github": "GitHub", "vuldb": "VulDB", "mitre": "MITRE", "hackerone": "HackerOne",
               "wordfence": "Wordfence", "patchstack": "Patchstack", "redhat": "Red Hat"}  # fmt: skip
    if name in special:
        return special[name]
    return (names or {}).get(re.sub(r"[^a-z0-9]", "", name)) or name.capitalize()


def short_cwe(name: str) -> str:
    """'Improper Neutralization of ... ('OS Command Injection')' -> 'OS Command Injection'."""
    if "('" in name and name.endswith("')"):
        return name[name.index("('") + 2 : -2]
    return re.sub(r"\s*\(.*?\)", "", name)


def exploit_label(flags: list[str]) -> str:
    full = f"Public exploit code ({', '.join(flags)})"
    if len(full) <= LABEL_MAX or len(flags) == 1:
        return clip(full)
    return f"Public exploit code ({flags[0]} +{len(flags) - 1} more)"


def short_label(
    name: str, row, cwe_names: dict[str, str] | None = None, org_names: dict[str, str] | None = None
) -> str | None:
    """Under 45 characters, true for the row whatever the sign of its contribution."""
    if name == "exploit":
        flags = [label for column, label in SHORT_FLAGS.items() if row.get(column) == 1]
        return exploit_label(flags) if flags else "No public exploit code yet"
    if name == "epss":
        pct = row.get("epss_pct")
        if not present(pct):
            return "No EPSS score yet"
        return f"EPSS above {math.floor(pct * 100)}% of CVEs that month"
    if name == "assigner":
        n = row.get("assigner_kev_prior")
        org = organisation(row.get("assigner"), org_names)
        if not present(n) or n <= 0:
            return clip(f"{org}: no earlier KEV entries")
        return clip(f"{org}: {int(n):,} earlier KEV entr{'y' if int(n) == 1 else 'ies'}")
    if name == "similarity":
        sim = row.get("kev_sim_max")
        return None if not present(sim) else f"Resembles exploited CVEs ({sim:.2f})"
    if name in SHORT_KEYWORDS:
        return SHORT_KEYWORDS[name] if row.get(name) == 1 else None
    if name == "cvss":
        score = row.get("cvss3_score")
        if not present(score):
            return None
        parts = []
        if row.get("attack_vector") == "NETWORK":
            parts.append("Network")
        if row.get("privileges_required") == "NONE":
            parts.append("no privileges")
        lead = ", ".join(parts)
        return clip(f"{lead} (CVSS {score:.1f})" if lead else f"CVSS {score:.1f} from the vendor")
    if name == "cwe":
        cwe = row.get("cwe_primary")
        if not present(cwe) or cwe in ("unknown", "other"):
            return None
        title = (cwe_names or {}).get(cwe) or cwe
        return clip(f"Weakness: {short_cwe(title)}")
    return None


def bars_from_contributions(
    contributions: np.ndarray,
    feature_names: list[str],
    raw: pd.DataFrame,
    k: int = 3,
    cwe_names: dict[str, str] | None = None,
    org_names: dict[str, str] | None = None,
) -> list[list[dict]]:
    """Up to k reason bars per row: {kind, label, value}, value = the family's summed SHAP
    contribution (log-odds). Positive families first (largest first), then negative ones
    (most negative first), skipping any that can't be stated truthfully."""
    families = [family(f) for f in feature_names]
    names = sorted({f for f in families if f})
    index = {name: i for i, name in enumerate(names)}
    totals = np.zeros((contributions.shape[0], len(names)))
    for j, fam in enumerate(families):
        if fam:
            totals[:, index[fam]] += contributions[:, j]
    out = []
    for i, row in enumerate(raw.to_dict("records")):
        values = totals[i]
        order = sorted(range(len(names)), key=lambda j: (values[j] <= 0, -abs(values[j])))
        bars = []
        for j in order:
            if len(bars) == k:
                break
            label = short_label(names[j], row, cwe_names, org_names)
            if label:
                bars.append({"kind": KIND.get(names[j], "exposure"), "label": label,
                             "value": round(float(values[j]), 4)})  # fmt: skip
        out.append(bars)
    return out


def shap_values(booster, X: pd.DataFrame) -> np.ndarray:
    import shap

    values = shap.TreeExplainer(booster).shap_values(X)
    if isinstance(values, list):  # older shap: one array per class
        values = values[-1]
    return np.asarray(values)


def top_reasons(booster, X: pd.DataFrame, raw_df: pd.DataFrame, k: int = 3, cwe_names=None):
    """Up to k reasons per row of X (raw_df holds the same rows' raw values, including
    assigner and the uncollapsed cwe_primary)."""
    contributions = shap_values(booster, X)
    return reasons_from_contributions(contributions, list(X.columns), raw_df, k, cwe_names)


def load_org_names(con) -> dict[str, str]:
    """Vendor key -> CISA's display name, for assigner organisations."""
    try:
        rows = con.execute(
            "SELECT vendor_key, mode(vendor) FROM clean.kev "
            "WHERE vendor_key IS NOT NULL AND vendor IS NOT NULL GROUP BY 1"
        ).fetchall()
    except Exception:  # noqa: BLE001 - no KEV table
        return {}
    return {k: v for k, v in rows if k and v}


def load_cwe_names(con) -> dict[str, str]:
    return dict(con.execute("SELECT cwe_id, name FROM weakness_types").fetchall())
