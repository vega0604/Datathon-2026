"""Unit tests for the SHE-52 grid and selection rule."""

from backend.modeling import tune


def row(leaves, child, trees, cap, primary, primary_500=0.0, reversed_=None):
    return {
        "num_leaves": leaves,
        "min_child_samples": child,
        "learning_rate": 0.03 if trees == 600 else 0.1,
        "n_estimators": trees,
        "max_pos_weight": cap,
        "primary_hits_at_k": primary,
        "primary_hits_at_500": primary_500,
        "reversed_hits_at_k": reversed_,
    }


def test_grid():
    combos = tune.grid()
    assert len(combos) == 3 * 3 * 2 * 3
    keys = {tuple(c[k] for k in tune.TUNED_KEYS) for c in combos}
    assert len(keys) == len(combos)
    assert {(c["learning_rate"], c["n_estimators"]) for c in combos} == {(0.03, 600), (0.1, 200)}


def test_finalists_by_primary_then_500_then_simplicity():
    rows = [
        row(31, 20, 600, 200, primary=12.0),
        row(7, 100, 200, 1, primary=11.0, primary_500=15.0),
        row(15, 50, 200, 1, primary=11.0, primary_500=15.0),
        row(7, 20, 200, 1, primary=11.0, primary_500=16.0),
        row(7, 20, 200, 1, primary=5.0),
    ]
    picked = tune.finalists(rows, n=3)
    assert [(r["num_leaves"], r["min_child_samples"]) for r in picked] == [
        (31, 20),
        (7, 20),
        (7, 100),
    ]


def test_pick_uses_the_sum_not_2025_alone():
    rows = [
        row(31, 20, 600, 200, primary=14.0, reversed_=3.0),
        row(15, 50, 200, 10, primary=12.0, reversed_=6.0),
        row(7, 100, 200, 1, primary=20.0),  # no time-reversed result: not eligible
    ]
    assert tune.pick(rows)["num_leaves"] == 15


def test_pick_tie_goes_to_the_simpler_model():
    rows = [
        row(15, 50, 200, 10, primary=12.0, reversed_=6.0),
        row(7, 50, 200, 10, primary=13.0, reversed_=5.0),
        row(7, 100, 200, 10, primary=11.0, reversed_=7.0),
    ]
    best = tune.pick(rows)
    assert (best["num_leaves"], best["min_child_samples"]) == (7, 100)
