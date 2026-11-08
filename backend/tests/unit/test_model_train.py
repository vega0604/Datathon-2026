"""Unit tests for the SHE-51 feature preparation and LightGBM training, on tiny frames."""

import numpy as np
import pandas as pd

from backend.modeling import features as mf
from backend.modeling import train as tr
from backend.pipeline.features import check_columns


def test_whitelist_passes_the_banned_column_guard():
    assert check_columns(mf.FEATURES) == []
    assert len(mf.FEATURES) == len(set(mf.FEATURES))
    for never in ("cve_id", "label", "assigner", "epss", "fold", "snapshot_end"):
        assert never not in mf.FEATURES


def test_prepare_maps_rare_and_unseen_categories_to_other():
    train = pd.DataFrame(
        {"cwe_primary": ["CWE-79"] * 40 + ["CWE-1"] * 3, "attack_vector": ["NETWORK"] * 43}
    )
    X, categories = mf.prepare(train, features=["cwe_primary", "attack_vector"])
    assert categories["cwe_primary"] == ["CWE-79", "other"]  # CWE-1 is rare (< 30)
    assert X["cwe_primary"].iloc[-1] == "other"
    score = pd.DataFrame({"cwe_primary": ["CWE-999", None], "attack_vector": ["LOCAL", "NETWORK"]})
    Xs, same = mf.prepare(score, categories, features=["cwe_primary", "attack_vector"])
    assert same is categories
    assert Xs["cwe_primary"].iloc[0] == "other"  # unseen
    assert pd.isna(Xs["cwe_primary"].iloc[1])  # NULL stays missing
    assert Xs["attack_vector"].tolist() == ["other", "NETWORK"]
    assert list(Xs["cwe_primary"].cat.categories) == ["CWE-79", "other"]


def test_fit_and_score_rank_positives_first():
    rng = np.random.default_rng(0)
    n = 400
    label = (np.arange(n) % 20 == 0).astype(int)
    df = pd.DataFrame(
        {
            "cve_id": [f"CVE-{i:04d}" for i in range(n)],
            "label": label,
            "epss_pct": label.astype(float),  # equals the label
            "nuclei": rng.integers(0, 2, n),
        }
    )
    params = {**tr.DEFAULT_PARAMS, "min_child_samples": 5, "n_estimators": 30}
    # One feature only: with feature_fraction 0.8 of two, some trees would see just noise.
    booster, categories = tr.fit(df, params, seed=0, features=["epss_pct"])
    scores = tr.score(booster, df, categories, features=["epss_pct"])
    assert scores[df["label"] == 1].min() > scores[df["label"] == 0].max()


def test_rank_average_breaks_ties_with_mean_probability():
    a = pd.Series([0.9, 0.1, 0.5])
    b = pd.Series([0.2, 0.8, 0.5])
    ens = tr.rank_average([a, b])
    assert ens["rank_avg"].tolist() == [2 / 3, 2 / 3, 2 / 3]
    assert ens["mean_prob"].tolist() == [0.55, 0.45, 0.5]


def test_pos_weight_is_capped():
    p, rounds = tr.lgb_params(tr.DEFAULT_PARAMS, seed=3, scale_pos_weight=5.0)
    assert p["objective"] == "binary"
    assert p["seed"] == 3
    assert "n_estimators" not in p
    assert rounds == 300
