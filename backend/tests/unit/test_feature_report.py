"""Unit tests for the SHE-117 univariate feature report."""

import math

import duckdb
import numpy as np
import pandas as pd
import pytest

from backend.modeling import feature_report as fr


def test_auc_and_direction():
    labels = pd.Series([0, 0, 1, 1])
    up = fr.auc_direction(pd.Series([0.1, 0.2, 0.8, 0.9]), labels)
    assert up == {"auc": 1.0, "auc_dir": 1.0, "direction": "+"}
    down = fr.auc_direction(pd.Series([0.9, 0.7, 0.2, 0.1]), labels)
    assert (down["auc"], down["auc_dir"], down["direction"]) == (0.0, 1.0, "-")
    mixed = fr.auc_direction(pd.Series([0.1, 0.6, 0.5, 0.9]), labels)  # 3 of 4 pairs right
    assert mixed["auc"] == pytest.approx(0.75)


def test_nulls_are_excluded_from_auc_and_ranked_last():
    labels = pd.Series([1, 0, 0, 1])
    values = pd.Series([np.nan, 0.1, 0.2, 0.9])
    assert fr.auc_direction(values, labels)["auc"] == 1.0  # the NULL positive is left out
    con = duckdb.connect()
    con.execute(
        "CREATE TABLE pop AS SELECT * FROM (VALUES ('A', 2024, 1), ('B', 2024, 0), "
        "('C', 2024, 0), ('D', 2024, 1)) AS t(cve_id, fold, label)"
    )
    from backend.modeling.evaluate import evaluate_frame

    part = pd.DataFrame({"cve_id": ["A", "B", "C", "D"], "fold": 2024})
    r = evaluate_frame(con, 2024, pd.DataFrame({"cve_id": part["cve_id"], "score": values}),
                       population="pop")  # fmt: skip
    assert r["k"] == 0  # tiny fold: scaled K rounds to 0
    ranked = fr.oriented(values, "+")
    lift = fr.top_lift(ranked, labels, part["cve_id"], share=0.25)  # top 1 row: D (0.9)
    assert lift == pytest.approx(1 / 0.5)


def test_stability_rule():
    def fold(auc_dir, direction):
        return {"auc_dir": auc_dir, "direction": direction}

    stable = fr.stability({2024: fold(0.70, "+"), 2025: fold(0.60, "+")})
    assert stable["stable"] and not stable["flips"] and stable["direction"] == "+"
    flip = fr.stability({2024: fold(0.70, "+"), 2025: fold(0.65, "-")})
    assert flip["flips"] and not flip["stable"] and flip["direction"] is None
    weak = fr.stability({2024: fold(0.70, "+"), 2025: fold(0.54, "+")})
    assert not weak["stable"] and not weak["flips"]
    assert fr.stability({2024: fold(0.91, "+"), 2025: fold(0.6, "+")})["suspect"]
    assert weak["mean_auc_dir"] == pytest.approx(0.62)


def test_cross_fold_category_scoring_uses_the_other_fold():
    this = pd.Series(["NETWORK", "LOCAL", "PHYSICAL"])
    other = pd.Series(["NETWORK", "NETWORK", "LOCAL", "LOCAL"])
    other_labels = pd.Series([1, 1, 0, 1])
    scores = fr.cross_fold_scores(this, other, other_labels)
    assert scores.tolist() == [1.0, 0.5, 0.75]  # PHYSICAL unseen: the other fold's base rate


def test_cwe_collapse():
    values = pd.Series(["CWE-79"] * 3 + ["CWE-1"])
    assert fr.collapse_cwe(values, min_rows=2).tolist() == ["CWE-79"] * 3 + ["other"]


def test_redundancy_threshold():
    x = np.arange(100, dtype=float)
    frame = pd.DataFrame({"a": x, "b": x * 2 + 1, "c": -x, "d": np.sin(x)})
    pairs = fr.redundant_pairs(frame, threshold=0.85)
    found = {(p["feature_a"], p["feature_b"]) for p in pairs}
    assert found == {("a", "b"), ("a", "c"), ("b", "c")}
    assert all(abs(p["rho"]) >= 0.85 for p in pairs)
    assert math.isclose(abs(pairs[0]["rho"]), 1.0)
