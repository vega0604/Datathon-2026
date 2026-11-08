"""SHE-115: a logistic regression check on the core features.

    uv run python -m backend.modeling.logreg

Features: the core set (signals, assigner history, similarity), all numeric. NULLs are
filled with the training median, with a 0/1 `<col>_missing` flag for epss_pct and the
similarity columns, plus two interactions: any_exploit_code x epss_pct and
any_exploit_code x assigner_kev_rate. Standardised (fitted on the training fold only),
class_weight="balanced", C in {0.01, 0.1, 1} chosen by the primary score (ties to the
smaller C, the stronger regularisation). Deterministic, so one run per setting, under both
label modes.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from backend.db.warehouse import connect
from backend.modeling import comparison
from backend.modeling import features as mf
from backend.modeling.evaluate import evaluate_frame
from backend.modeling.labels import LABEL_ENDS, LABEL_MODES, train_labels
from backend.modeling.train import PROTOCOLS

C_GRID = (0.01, 0.1, 1.0)
MISSING_FLAGS = ["epss_pct", "kev_sim_max", "kev_sim_top5"]
INTERACTIONS = [("any_exploit_code", "epss_pct"), ("any_exploit_code", "assigner_kev_rate")]


@dataclass
class LogReg:
    medians: pd.Series
    scaler: StandardScaler
    model: LogisticRegression
    columns: list[str]


def design(df: pd.DataFrame, medians: pd.Series | None = None) -> tuple[pd.DataFrame, pd.Series]:
    """Model matrix for the core features; medians come from the training fold."""
    X = df[mf.CORE].astype(float)
    flags = X[MISSING_FLAGS].isna().astype(float).add_suffix("_missing")
    if medians is None:
        medians = X.median()
    X = X.fillna(medians)
    for a, b in INTERACTIONS:
        X[f"{a}_x_{b}"] = X[a] * X[b]
    return pd.concat([X, flags], axis=1), medians


def fit(train_df: pd.DataFrame, C: float) -> LogReg:
    X, medians = design(train_df)
    scaler = StandardScaler().fit(X)
    model = LogisticRegression(C=C, class_weight="balanced", max_iter=5_000)
    model.fit(scaler.transform(X), train_df["label"].astype(int))
    return LogReg(medians, scaler, model, list(X.columns))


def score(fitted: LogReg, df: pd.DataFrame) -> pd.Series:
    X, _ = design(df, fitted.medians)
    return pd.Series(fitted.model.decision_function(fitted.scaler.transform(X)), index=df.index)


def run(con, data: pd.DataFrame, C: float, direction: str, label_mode: str) -> tuple[dict, LogReg]:
    p = PROTOCOLS[direction]
    train_df = data[data["fold"].isin(p["train"])]
    if label_mode == "long":
        train_df = train_df.assign(label=train_labels(con, train_df, LABEL_ENDS[direction]))
    fitted = fit(train_df, C)
    test_df = data[data["fold"] == p["test"]]
    scores = pd.DataFrame({"cve_id": test_df["cve_id"], "score": score(fitted, test_df)})
    return comparison.single(evaluate_frame(con, p["test"], scores)), fitted


def coefficients(fitted: LogReg) -> pd.Series:
    """Standardised coefficients, largest effect first."""
    coefs = pd.Series(fitted.model.coef_[0], index=fitted.columns)
    return coefs.reindex(coefs.abs().sort_values(ascending=False).index)


def main() -> None:
    con = connect()
    data = mf.load(con, folds=(2024, 2025))
    best_overall = None
    for label_mode in LABEL_MODES:
        by_c = {}
        for C in C_GRID:
            by_c[C] = {d: run(con, data, C, d, label_mode) for d in comparison.DIRECTIONS}
            results = {d: r for d, (r, _) in by_c[C].items()}
            print(f"{label_mode:<9} C={C:<5} primary {comparison.primary_score(results):.1f}")
        best_c = min(
            C_GRID,
            key=lambda c: (-comparison.primary_score({d: r for d, (r, _) in by_c[c].items()}), c),
        )
        results = {d: r for d, (r, _) in by_c[best_c].items()}
        comparison.upsert(comparison.rows_for("logreg", label_mode, results))
        score_ = comparison.primary_score(results)
        if best_overall is None or score_ > best_overall[0]:
            best_overall = (score_, label_mode, best_c, by_c[best_c]["primary"][1])
        print(f"chosen for {label_mode}: C={best_c}, primary {score_:.1f}")
    score_, label_mode, best_c, fitted = best_overall
    print(f"\nCoefficients (standardised), {label_mode} labels, C={best_c}, train 2024:")
    for name, value in coefficients(fitted).items():
        print(f"  {name:<36} {value:+.3f}")
    comparison.print_rows([r for r in comparison.read() if r["variant"] == "logreg"])


if __name__ == "__main__":
    np.seterr(all="ignore")
    main()
