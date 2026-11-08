"""SHE-51: a LightGBM ranker, backtested on fold 2025 (primary) and 2024 (time-reversed).

    uv run python -m backend.modeling.train

Primary protocol: train on 2024, test on 2025 (hits@243 and hits@500). Secondary, for
robustness only: train on 2025, test on 2024 ("time-reversed"). Every result is the mean,
min and max over 5 seeds, plus the rank-averaged ensemble of the 5, which is what final
scoring uses. There is no early stopping on the test fold. Parameters come from
modeling/params.json when it exists (SHE-52), else DEFAULT_PARAMS.

Writes outputs/model_results.csv, outputs/logs/train_log.json and the boosters to
models/train/.
"""

import csv
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

from backend.core.config import BACKEND_DIR, LOGS_DIR, OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling import features as mf
from backend.modeling.evaluate import evaluate_frame

MODELS_DIR = BACKEND_DIR / "models"
PARAMS_PATH = Path(__file__).with_name("params.json")
SEEDS = (0, 1, 2, 3, 4)
MAX_POS_WEIGHT = 200
# Conservative for a few dozen positives.
DEFAULT_PARAMS = {
    "num_leaves": 15,
    "min_child_samples": 50,
    "learning_rate": 0.05,
    "n_estimators": 300,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "lambda_l2": 1.0,
}
PROTOCOLS = {
    "primary": {"train": (2024,), "test": 2025},
    "time_reversed": {"train": (2025,), "test": 2024},
}


def load_params() -> dict:
    if PARAMS_PATH.exists():
        return {**DEFAULT_PARAMS, **json.loads(PARAMS_PATH.read_text())}
    return dict(DEFAULT_PARAMS)


def lgb_params(params: dict, seed: int, scale_pos_weight: float) -> tuple[dict, int]:
    """LightGBM's own parameter dict and the number of boosting rounds."""
    p = {k: v for k, v in params.items() if k not in ("n_estimators", "max_pos_weight")}
    p.update(
        objective="binary",
        scale_pos_weight=scale_pos_weight,
        seed=seed,
        deterministic=True,
        force_row_wise=True,
        num_threads=4,
        verbose=-1,
    )
    return p, int(params["n_estimators"])


def fit(
    train_df: pd.DataFrame,
    params: dict,
    seed: int,
    features: list[str] = mf.FEATURES,
    categories: dict | None = None,
) -> tuple[lgb.Booster, dict]:
    """Train on rows with a label; return the booster and the categories it was fit with."""
    X, categories = mf.prepare(train_df, categories, features=features)
    y = train_df["label"].astype(int)
    positives = int(y.sum())
    if positives == 0:
        raise ValueError("no positive labels in the training data")
    # scale_pos_weight = negatives/positives, capped (SHE-52 tunes the cap).
    cap = params.get("max_pos_weight", MAX_POS_WEIGHT)
    weight = min((len(y) - positives) / positives, cap)
    p, rounds = lgb_params(params, seed, weight)
    booster = lgb.train(p, lgb.Dataset(X, y, free_raw_data=False), num_boost_round=rounds)
    return booster, categories


def score(
    booster: lgb.Booster, df: pd.DataFrame, categories: dict, features: list[str] = mf.FEATURES
) -> pd.Series:
    """Predicted probabilities, indexed like df."""
    X, _ = mf.prepare(df, categories, features=features)
    return pd.Series(booster.predict(X), index=df.index)


def rank_average(scores: list[pd.Series]) -> pd.DataFrame:
    """Ensemble: mean of each seed's percentile rank (ties averaged), with the mean
    probability kept to break ties."""
    frame = pd.concat(scores, axis=1)
    return pd.DataFrame(
        {"rank_avg": frame.rank(pct=True).mean(axis=1), "mean_prob": frame.mean(axis=1)}
    )


ENSEMBLE_ORDER = "rank_avg DESC, mean_prob DESC"


def summarise(values: list[int]) -> dict:
    return {"mean": float(np.mean(values)), "min": int(min(values)), "max": int(max(values))}


def backtest(
    con,
    data: pd.DataFrame,
    params: dict,
    train_folds: tuple[int, ...],
    test_fold: int,
    seeds=SEEDS,
    features: list[str] = mf.FEATURES,
    keep_models: bool = False,
) -> dict:
    """Fit once per seed on train_folds, evaluate each seed and their rank-averaged
    ensemble on test_fold."""
    train_df = data[data["fold"].isin(train_folds)]
    test_df = data[data["fold"] == test_fold]
    per_seed, seed_scores, models = [], [], []
    for seed in seeds:
        booster, categories = fit(train_df, params, seed, features)
        s = score(booster, test_df, categories, features)
        seed_scores.append(s)
        r = evaluate_frame(con, test_fold, pd.DataFrame({"cve_id": test_df["cve_id"], "score": s}))
        per_seed.append({"seed": seed, **r})
        if keep_models:
            models.append((seed, booster, categories))
    ensemble = rank_average(seed_scores).assign(cve_id=test_df["cve_id"])
    ens = evaluate_frame(con, test_fold, ensemble, order_by=ENSEMBLE_ORDER)
    result = {
        "train_folds": list(train_folds),
        "test_fold": test_fold,
        "k": per_seed[0]["k"],
        "positives": per_seed[0]["positives"],
        "per_seed": per_seed,
        "hits_at_k": summarise([r["hits_at_k"] for r in per_seed]),
        "hits_at_500": summarise([r["hits_at_500"] for r in per_seed]),
        "ensemble": {"hits_at_k": ens["hits_at_k"], "hits_at_500": ens["hits_at_500"]},
    }
    if keep_models:
        result["models"] = models
    return result


def save_models(models, folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for seed, booster, categories in models:
        booster.save_model(str(folder / f"seed{seed}.lgb"))
    (folder / "categories.json").write_text(json.dumps(models[0][2], indent=2) + "\n")


def result_rows(name: str, result: dict) -> list[dict]:
    base = {"protocol": name, "test_fold": result["test_fold"], "k": result["k"]}
    rows = [
        {**base, "model": f"seed{r['seed']}", "hits_at_k": r["hits_at_k"],
         "hits_at_500": r["hits_at_500"]}
        for r in result["per_seed"]
    ]  # fmt: skip
    for stat in ("mean", "min", "max"):
        rows.append(
            {**base, "model": stat, "hits_at_k": result["hits_at_k"][stat],
             "hits_at_500": result["hits_at_500"][stat]}
        )  # fmt: skip
    rows.append({**base, "model": "ensemble", **result["ensemble"]})
    return rows


def describe(name: str, result: dict) -> str:
    k, h = result["hits_at_k"], result["hits_at_500"]
    label = " (time-reversed)" if name == "time_reversed" else ""
    return (
        f"{name}{label}: train {result['train_folds']} -> test {result['test_fold']} "
        f"({result['positives']} positives)\n"
        f"  hits@{result['k']}: mean {k['mean']:.1f} [{k['min']}-{k['max']}], "
        f"ensemble {result['ensemble']['hits_at_k']}\n"
        f"  hits@500: mean {h['mean']:.1f} [{h['min']}-{h['max']}], "
        f"ensemble {result['ensemble']['hits_at_500']}"
    )


def main() -> None:
    con = connect()
    data = mf.load(con, folds=(2024, 2025))
    params = load_params()
    log = {"params": params, "seeds": list(SEEDS), "protocols": {}}
    rows = []
    for name, protocol in PROTOCOLS.items():
        result = backtest(con, data, params, protocol["train"], protocol["test"], keep_models=True)
        save_models(result.pop("models"), MODELS_DIR / "train" / name)
        log["protocols"][name] = result
        rows += result_rows(name, result)
        print(describe(name, result))
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUTS_DIR / "model_results.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "train_log.json").write_text(json.dumps(log, indent=2) + "\n")


if __name__ == "__main__":
    main()
