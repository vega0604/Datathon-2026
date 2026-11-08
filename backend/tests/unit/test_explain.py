"""Unit tests for the SHE-56 reason templates."""

import numpy as np
import pandas as pd

from backend.modeling import explain as ex

ROW = {
    "exploitdb": 0,
    "metasploit": 1,
    "nuclei": 1,
    "poc_github": 0,
    "any_exploit_code": 1,
    "epss_pct": 0.973,
    "assigner": "secure@microsoft.com",
    "assigner_kev_prior": 312,
    "kev_sim_max": 0.934,
    "kw_unauthenticated": 1,
    "kw_sql_injection": 0,
    "attack_vector": "NETWORK",
    "privileges_required": "NONE",
    "user_interaction": "REQUIRED",
    "attack_complexity": "HIGH",
    "cvss3_score": 9.8,
    "cwe_primary": "CWE-79",
    "days_to_cutoff": 200,
}


def test_each_family_template():
    names = {"CWE-79": "Improper Neutralization of Input During Web Page Generation"}
    assert ex.render("exploit", ROW) == "Public exploit code exists (Metasploit, Nuclei)"
    assert ex.render("epss", ROW) == "EPSS is higher than 97% of vulnerabilities that month"
    assert ex.render("assigner", ROW) == (
        "secure@microsoft.com has had 312 vulnerabilities added to KEV before"
    )
    assert ex.render("similarity", ROW) == (
        "Description closely resembles known-exploited vulnerabilities (similarity 0.93)"
    )
    assert ex.render("kw_unauthenticated", ROW) == "Description mentions unauthenticated access"
    assert (
        ex.render("cvss", ROW) == "Reachable over the network with no privileges needed (CVSS 9.8)"
    )
    assert ex.render("cwe", ROW, names) == f"Weakness type: {names['CWE-79']}"


def test_nothing_is_invented():
    quiet = {**ROW, "metasploit": 0, "nuclei": 0, "kw_unauthenticated": 0, "epss_pct": None,
             "assigner_kev_prior": 0, "kev_sim_max": float("nan"), "cwe_primary": "unknown"}  # fmt: skip
    for name in ("exploit", "epss", "assigner", "similarity", "kw_unauthenticated", "cwe"):
        assert ex.render(name, quiet) is None


def test_uuid_assigner_and_singular():
    row = {**ROW, "assigner": "416baaa9-dc9f-4396-8d5f-8c081fb06d67", "assigner_kev_prior": 1}
    assert ex.render("assigner", row) == (
        "Its assigning organisation has had 1 vulnerability added to KEV before"
    )


def test_missing_cwe_name_falls_back_to_the_id():
    assert ex.render("cwe", {**ROW, "cwe_primary": "CWE-1234"}, {}) == "Weakness type: CWE-1234"


def test_days_to_cutoff_is_skipped_and_families_are_merged():
    assert ex.family("days_to_cutoff") is None
    features = ["days_to_cutoff", "metasploit", "nuclei", "epss_pct", "kw_sql_injection"]
    contributions = np.array([[9.0, 0.4, 0.4, 0.5, 0.3]])
    reasons = ex.reasons_from_contributions(contributions, features, pd.DataFrame([ROW]), k=3)
    # exploit (0.8) beats epss (0.5); kw_sql_injection is positive but its flag is 0.
    assert reasons == [
        [
            "Public exploit code exists (Metasploit, Nuclei)",
            "EPSS is higher than 97% of vulnerabilities that month",
        ]
    ]


def test_only_positive_contributions_and_at_most_k():
    features = ["epss_pct", "metasploit", "kev_sim_max", "kw_unauthenticated", "cwe_primary"]
    raw = pd.DataFrame([ROW])
    assert ex.reasons_from_contributions(np.array([[-1.0, -0.1, 0, -2, -3]]), features, raw) == [[]]
    four = ex.reasons_from_contributions(np.array([[0.5, 0.4, 0.3, 0.2, 0.1]]), features, raw, k=3)
    assert len(four[0]) == 3
