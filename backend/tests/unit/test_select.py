"""Unit tests for the SHE-116 selection rule."""

from backend.modeling.select import decide


def rows(variant, labels, primary, reversed_):
    score = primary + reversed_
    return [
        {"variant": variant, "labels": labels, "direction": "primary",
         "hits_at_k_mean": primary, "primary_score": score},
        {"variant": variant, "labels": labels, "direction": "time_reversed",
         "hits_at_k_mean": reversed_, "primary_score": score},
    ]  # fmt: skip


CURRENT = rows("lgbm_she8", "benchmark", 10.0, 8.0)  # primary score 18


def test_clear_win():
    d = decide(CURRENT + rows("blend_a0.5", "long", 13.0, 9.0))  # 22: +4, better both ways
    assert d["winner"] == {"variant": "blend_a0.5", "labels": "long"}


def test_win_in_one_direction_only_is_not_enough():
    d = decide(CURRENT + rows("safety", "none", 16.0, 5.0))  # 21: +3, but worse on 2024
    assert d["winner"] is None
    assert not d["candidates"][0]["time_reversed_ok"]


def test_margin_below_3():
    d = decide(CURRENT + rows("logreg", "long", 11.0, 9.5))  # 20.5: +2.5
    assert d["winner"] is None
    assert not d["candidates"][0]["margin_ok"]


def test_best_clear_winner_is_picked():
    d = decide(CURRENT + rows("a", "long", 12.0, 9.0) + rows("b", "long", 13.0, 10.0))
    assert d["winner"]["variant"] == "b"
