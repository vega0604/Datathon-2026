"""Unit tests for the SHE-48 safety ranker on tiny frames."""

import duckdb
import pandas as pd
import pytest

from backend.modeling.evaluate import ranked_sql
from backend.modeling.safety import assigner_pct, choose, safety_score


def frame():
    return pd.DataFrame(
        {
            "cve_id": ["CVE-1", "CVE-2", "CVE-3"],
            "fold": [2024, 2024, 2024],
            "epss_pct": [0.5, None, 0.9],
            "any_exploit_code": [1, 0, 0],
            "assigner_kev_prior": [10, 0, 5],
        }
    )


def test_score_arithmetic():
    # assigner_pct over (10, 0, 5) = (1.0, 0.0, 0.5)
    score = safety_score(frame(), w_code=2.0, w_vendor=0.5)
    assert score.tolist() == pytest.approx([0.5 + 2.0 + 0.5, 0.0, 0.9 + 0.25])


def test_null_epss_counts_as_zero():
    assert safety_score(frame(), w_code=0.0, w_vendor=0.0).tolist() == pytest.approx(
        [0.5, 0.0, 0.9]
    )


def test_assigner_pct_is_within_each_fold():
    prior = pd.Series([1, 2, 3, 7])
    fold = pd.Series([2024, 2024, 2025, 2025])
    assert assigner_pct(prior, fold).tolist() == [0.0, 1.0, 0.0, 1.0]
    assert assigner_pct(pd.Series([4]), pd.Series([2024])).tolist() == [0.0]  # lone row


def test_ties_broken_by_cve_id():
    con = duckdb.connect()
    con.register("s", pd.DataFrame({"cve_id": ["CVE-9", "CVE-2"], "fold": 2024, "score": 1.0}))
    ranked = con.execute(
        f"SELECT cve_id FROM ({ranked_sql('s', 2024, 'score DESC')}) ORDER BY rank"
    ).fetchall()
    assert ranked == [("CVE-2",), ("CVE-9",)]


def test_choose_uses_only_the_selection_fold():
    results = [
        {"fold": 2024, "w_code": 1, "w_vendor": 0, "hits_at_k": 5, "hits_at_500": 9},
        {"fold": 2024, "w_code": 2, "w_vendor": 0, "hits_at_k": 5, "hits_at_500": 10},
        {"fold": 2025, "w_code": 1, "w_vendor": 0, "hits_at_k": 30, "hits_at_500": 40},
    ]
    assert choose(results)["w_code"] == 2
