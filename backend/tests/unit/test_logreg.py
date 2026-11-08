"""Unit tests for the SHE-115 logistic regression check."""

import numpy as np
import pandas as pd
import pytest

from backend.modeling import features as mf
from backend.modeling import logreg


def frame(n=40, seed=0, shift=0.0):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({c: rng.uniform(0, 1, n) + shift for c in mf.CORE})
    df["any_exploit_code"] = (rng.uniform(size=n) > 0.5).astype(float)
    df["label"] = (df["epss_pct"] > 0.7).astype(int)
    return df


def test_missing_flags_and_median_fill():
    df = frame()
    df.loc[0, "epss_pct"] = np.nan
    df.loc[1, "kev_sim_max"] = np.nan
    X, medians = logreg.design(df)
    assert X.loc[0, "epss_pct_missing"] == 1.0
    assert X.loc[1, "kev_sim_max_missing"] == 1.0
    assert X.loc[2, "epss_pct_missing"] == 0.0
    assert X.loc[0, "epss_pct"] == pytest.approx(medians["epss_pct"])
    assert {f"{c}_missing" for c in logreg.MISSING_FLAGS} <= set(X.columns)


def test_interactions():
    X, _ = logreg.design(frame())
    assert np.allclose(X["any_exploit_code_x_epss_pct"], X["any_exploit_code"] * X["epss_pct"])
    assert np.allclose(
        X["any_exploit_code_x_assigner_kev_rate"], X["any_exploit_code"] * X["assigner_kev_rate"]
    )


def test_standardisation_uses_the_training_fold_only():
    train, test = frame(seed=1), frame(seed=2, shift=100.0)
    fitted = logreg.fit(train, C=1.0)
    X_train, _ = logreg.design(train)
    assert np.allclose(fitted.scaler.mean_, X_train.mean().to_numpy())
    test_medians_used = logreg.design(test, fitted.medians)[1]
    assert test_medians_used.equals(fitted.medians)
    assert len(logreg.score(fitted, test)) == len(test)
