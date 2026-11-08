"""Unit tests for the SHE-110 serving table: precedence, latest month, NULLs, percentiles."""

import duckdb
import numpy as np
import pandas as pd

from backend.modeling import serving


def group(confidence, ids, scores, order=None):
    df = pd.DataFrame(
        {"cve_id": ids, "confidence": confidence, "score_raw": scores,
         "reasons": [[f"{confidence} reason"] for _ in ids], "as_of": "2026-01"}
    )  # fmt: skip
    if order is not None:
        df["order"] = order
    return df


def test_precedence_kev_then_model_then_lower():
    exploited = group("exploited", ["A"], [1.0])
    model = group("model", ["A", "B"], [0.9, 0.8], order=[1.0, 0.5])
    lower = group("lower", ["A", "B", "C"], [3.0, 2.0, 1.0])
    unscored = group("lower", ["D"], [np.nan]).assign(reasons=[[]])
    out = serving.combine(exploited, model, lower, unscored).set_index("cve_id")
    assert out.loc["A", "confidence"] == "exploited"
    assert out.loc["B", "confidence"] == "model"
    assert out.loc["C", "confidence"] == "lower"
    assert list(out.index) == ["A", "B", "C", "D"]
    assert list(out.columns) == serving.COLUMNS[1:]


def test_null_scores_stay_null_and_percentiles_are_within_groups():
    exploited = group("exploited", ["K1", "K2"], [1.0, 1.0])
    model = group("model", ["M1", "M2"], [0.7, 0.7], order=[0.9, 0.4])  # tie broken by order
    lower = group("lower", ["L1", "L2", "L3"], [0.1, 0.5, 0.9])
    unscored = group("lower", ["N1"], [np.nan]).assign(reasons=[[]])
    out = serving.combine(exploited, model, lower, unscored).set_index("cve_id")
    assert out.loc[["K1", "K2"], "score_pct"].tolist() == [1.0, 1.0]
    assert out.loc[["M1", "M2"], "score_pct"].tolist() == [1.0, 0.5]
    assert out.loc[["L1", "L2", "L3"], "score_pct"].tolist() == [1 / 3, 2 / 3, 1.0]
    assert np.isnan(out.loc["N1", "score_pct"])
    assert np.isnan(out.loc["N1", "score_raw"])
    assert out.loc["N1", "reasons"] == []


def test_latest_signal_month_is_used():
    con = duckdb.connect()
    con.execute(
        """
        CREATE TABLE sig AS SELECT * FROM (VALUES
            ('CVE-1', '2025-03', 0.2::DOUBLE, 0, 0, 0, 0),
            ('CVE-1', '2025-11', 0.8::DOUBLE, 0, 1, 0, 0),
            ('CVE-2', '2024-06', 0.5::DOUBLE, 0, 0, 0, 0)
        ) AS t(cve_id, month, epss_pct, exploitdb, metasploit, nuclei, poc_github)
        """
    )
    rows = con.execute(
        f"SELECT cve_id, month, epss_pct, any_exploit_code, snapshot_end "
        f"FROM ({serving.latest_signals_sql('sig')}) ORDER BY cve_id"
    ).fetchall()
    assert [(r[0], r[1], r[2], r[3]) for r in rows] == [
        ("CVE-1", "2025-11", 0.8, 1),
        ("CVE-2", "2024-06", 0.5, 0),
    ]
    assert str(rows[0][4]) == "2025-11-30"


def test_rule_reasons():
    row = {"metasploit": 1, "nuclei": 0, "exploitdb": 0, "poc_github": 0, "epss_pct": 0.95,
           "assigner": "psirt@example.com", "assigner_kev_prior": 4}  # fmt: skip
    assert serving.rule_reasons(row) == [
        "Public exploit code exists (Metasploit)",
        "EPSS is higher than 95% of vulnerabilities that month",
        "psirt@example.com has had 4 vulnerabilities added to KEV before",
    ]
    quiet = {**row, "metasploit": 0, "epss_pct": 0.4, "assigner_kev_prior": 0}
    assert serving.rule_reasons(quiet) == []
