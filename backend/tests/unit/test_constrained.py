"""Unit tests for SHE-113: monotone vectors, the constrained grid, and monotone fits."""

import numpy as np
import pandas as pd

from backend.modeling import constrained
from backend.modeling import features as mf
from backend.modeling import train as tr


def test_monotone_vector_matches_each_feature_set():
    for name, features in mf.FEATURE_SETS.items():
        vector = mf.monotone_vector(features)
        assert len(vector) == len(features), name
        for feature, sign in zip(features, vector, strict=True):
            assert sign == mf.MONOTONE.get(feature, 0)
    assert sum(mf.monotone_vector(mf.FEATURES)) == 10
    assert set(mf.CORE) == set(
        mf.FEATURE_GROUPS["signals"]
        + mf.FEATURE_GROUPS["assigner_history"]
        + mf.FEATURE_GROUPS["similarity"]
    )


def test_grid_and_tie_break():
    grid = constrained.grid(base=tr.DEFAULT_PARAMS)
    assert len(grid) == 24
    assert all(p["max_depth"] == 3 and p["learning_rate"] == 0.02 and p["monotone"] for p in grid)
    simple, complex_ = (
        {"num_leaves": 3, "min_child_samples": 200, "n_estimators": 400, "feature_set": "core"},
        {"num_leaves": 7, "min_child_samples": 100, "n_estimators": 800, "feature_set": "all"},
    )
    assert constrained.ranked([(complex_, 10.0), (simple, 10.0)])[0][0] is simple
    assert constrained.ranked([(complex_, 11.0), (simple, 10.0)])[0][0] is complex_


def test_feature_set_selects_the_columns():
    assert tr.features_for({"feature_set": "core"}) == mf.CORE
    assert tr.features_for({}, ["epss_pct"]) == ["epss_pct"]


def test_constrained_feature_never_decreases():
    rng = np.random.default_rng(0)
    n = 3_000
    x = rng.uniform(0, 1, n)
    # The true relation goes up then down; the constraint must keep predictions rising.
    p = np.where(x < 0.5, x, 1 - x) * 0.6
    df = pd.DataFrame(
        {"epss_pct": x, "cvss3_score": rng.uniform(0, 10, n), "label": rng.uniform(size=n) < p}
    )
    params = {**tr.DEFAULT_PARAMS, "max_depth": 3, "num_leaves": 7, "min_child_samples": 20,
              "n_estimators": 100, "monotone": True, "max_pos_weight": 1}  # fmt: skip
    booster, categories = tr.fit(df, params, seed=0, features=["epss_pct", "cvss3_score"])
    for cvss in (1.0, 5.0, 9.0):
        grid = pd.DataFrame({"epss_pct": np.linspace(0, 1, 101), "cvss3_score": cvss})
        pred = tr.score(booster, grid, categories, features=["epss_pct", "cvss3_score"])
        assert (np.diff(pred.to_numpy()) >= -1e-12).all()
