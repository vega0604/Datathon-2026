"""Unit tests for the SHE-114 rank blend."""

import pandas as pd
import pytest

from backend.modeling.blend import blend, choose_alpha, pct_rank

MODEL = pd.Series([0.9, 0.1, 0.5, 0.3])
SAFETY = pd.Series([1.0, 3.0, 2.0, 0.5])


def order(scores: pd.Series) -> list[int]:
    return scores.sort_values(ascending=False, kind="mergesort").index.tolist()


def test_alpha_zero_and_one_reproduce_the_inputs():
    assert order(blend(MODEL, SAFETY, 0.0)) == order(SAFETY)
    assert order(blend(MODEL, SAFETY, 1.0)) == order(MODEL)


def test_rank_arithmetic_on_four_rows():
    assert pct_rank(MODEL).tolist() == [1.0, 0.25, 0.75, 0.5]
    assert pct_rank(SAFETY).tolist() == [0.5, 1.0, 0.75, 0.25]
    assert blend(MODEL, SAFETY, 0.5).tolist() == pytest.approx([0.75, 0.625, 0.75, 0.375])


def test_choose_alpha_by_primary_score_ties_to_smaller():
    def res(a, b):
        return {"primary": {"hits_at_k": {"mean": a}}, "time_reversed": {"hits_at_k": {"mean": b}}}

    results = {0.0: res(13, 5), 0.25: res(14, 7), 0.5: res(12, 9), 1.0: res(10, 8)}
    assert choose_alpha(results) == 0.25
