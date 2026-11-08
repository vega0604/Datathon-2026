"""Unit tests for the lean feature-set rule."""

import numpy as np
import pandas as pd

from backend.modeling import features as mf
from backend.modeling import lean


def stat(auc_dir=0.7, direction="+", positives=10):
    return {"auc": None, "auc_dir": auc_dir, "direction": direction, "positives_present": positives}


def stats(**overrides):
    """Every whitelisted feature fails (weak) unless overridden."""
    out = {f: stat(auc_dir=0.51) for f in mf.FEATURES}
    out.update(overrides)
    return out


def rows(n=200, seed=0):
    rng = np.random.default_rng(seed)
    return pd.DataFrame({f: rng.normal(size=n) for f in mf.FEATURES if f not in mf.CATEGORICAL})


def test_passes_rule():
    assert lean.passes([stat(), stat(0.6)])
    assert not lean.passes([stat(), stat(0.54)])  # weak in one fold
    assert not lean.passes([stat(), stat(direction="-")])  # flips
    assert not lean.passes([stat(positives=4), stat()])  # too few positives with a value
    assert not lean.passes([stat(direction=None)])


def test_selection_keeps_order_and_directions():
    s = {2024: stats(epss_pct=stat(0.6), n_cwes=stat(0.6, "-"), cwe_primary=stat(0.7)),
         2025: stats(epss_pct=stat(0.7), n_cwes=stat(0.6, "-"), cwe_primary=stat(0.7))}  # fmt: skip
    features, directions = lean.select_features(s, rows())
    assert features == ["epss_pct", "cwe_primary", "n_cwes"]  # whitelist order
    assert directions == {"epss_pct": 1, "n_cwes": -1}  # categorical: unconstrained


def test_redundant_pair_keeps_the_stronger():
    frame = rows()
    frame["kev_sim_top5"] = frame["kev_sim_max"] * 0.9 + 0.01  # rho = 1
    s = {2024: stats(kev_sim_max=stat(0.70), kev_sim_top5=stat(0.80))}
    features, _ = lean.select_features(s, frame)
    assert features == ["kev_sim_top5"]
    s = {2024: stats(kev_sim_max=stat(0.80), kev_sim_top5=stat(0.80))}  # tie: whitelist order
    assert lean.select_features(s, frame)[0] == ["kev_sim_max"]


def test_nested_selection_ignores_the_test_fold():
    """Selection for train 2024 uses only fold 2024: changing 2025 labels changes nothing."""
    rng = np.random.default_rng(1)
    n = 400
    data = pd.DataFrame({f: rng.normal(size=2 * n) for f in mf.FEATURES if f not in mf.CATEGORICAL})
    for c in mf.CATEGORICAL:
        data[c] = rng.choice(["A", "B"], size=2 * n)
    data["fold"] = [2024] * n + [2025] * n
    data["label"] = (rng.uniform(size=2 * n) < 0.1).astype(int)
    before = lean.feature_stats(data, 2024, 2024)
    data.loc[data["fold"] == 2025, "label"] = 1 - data.loc[data["fold"] == 2025, "label"]
    assert lean.feature_stats(data, 2024, 2024) == before


def test_lean_params():
    params = lean.lean_params({"num_leaves": 3, "feature_set": "all"}, {"epss_pct": 1})
    assert "feature_set" not in params
    assert params["monotone"] is True
    assert params["monotone_map"] == {"epss_pct": 1}
    assert mf.monotone_vector(["epss_pct", "n_cwes"], params["monotone_map"]) == [1, 0]
