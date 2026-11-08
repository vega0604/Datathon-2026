"""SHE-58: the final model and the submitted top 500.

    uv run python -m backend.modeling.final

Trains on 2024 + 2025 with modeling/params.json and 5 fixed seeds, scores fold 2026 (the
scoreboard) with each, and rank-averages across seeds (ties: mean probability, then
cve_id). Writes outputs/top500.csv through the validated writer, the boosters and
categories to models/final/, and the top 3 reasons for the top 500 (seed-0 booster) to
outputs/top500_reasons.csv. Nothing here reads 2026 labels; there are none.
"""

import csv
import json
import re
from collections import Counter

import lightgbm as lgb
import pandas as pd

from backend.core.config import LOGS_DIR, OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling import explain, safety
from backend.modeling import features as mf
from backend.modeling.labels import train_labels
from backend.modeling.safety import safety_score
from backend.modeling.submission import pick_top, write_submission
from backend.modeling.train import MODELS_DIR, SEEDS, fit, load_params, rank_average, save_models
from backend.modeling.train import score as predict

FINAL_DIR = MODELS_DIR / "final"
TRAIN_FOLDS = (2024, 2025)
SCORE_FOLD = 2026


# Which ranking the boosters in models/final/ serve (written with them): the variant, its
# feature list, and the safety blend weight (alpha 1 = the model alone).
FINAL_CONFIG = FINAL_DIR / "config.json"


def train_final(
    data: pd.DataFrame,
    params: dict,
    seeds=SEEDS,
    features: list[str] = mf.FEATURES,
    label_end: str | None = None,
    con=None,
) -> list[tuple]:
    """Train on 2024 + 2025, on the benchmark label or, with label_end, on KEV additions up
    to label_end (SHE-112 long labels; needs con)."""
    train_df = data[data["fold"].isin(TRAIN_FOLDS)]
    if label_end is not None:
        train_df = train_df.assign(label=train_labels(con, train_df, label_end))
    models = []
    for seed in seeds:
        booster, categories = fit(train_df, params, seed, features)
        models.append((seed, booster, categories))
    return models


def save_final(models: list[tuple], config: dict) -> None:
    save_models(models, FINAL_DIR)
    FINAL_CONFIG.write_text(json.dumps(config, indent=2) + "\n")


def final_config() -> dict:
    if FINAL_CONFIG.exists():
        return json.loads(FINAL_CONFIG.read_text())
    return {"variant": "lgbm_she8", "model": "lgbm_she8", "labels": "benchmark",
            "label_end": None, "alpha": 1.0, "features": mf.FEATURES, "params": load_params()}  # fmt: skip


def load_final_models() -> list[tuple]:
    categories = json.loads((FINAL_DIR / "categories.json").read_text())
    return [
        (seed, lgb.Booster(model_file=str(FINAL_DIR / f"seed{seed}.lgb")), categories)
        for seed in SEEDS
    ]


def ordered(out: pd.DataFrame, keys: list[str]) -> pd.DataFrame:
    """Sort by keys (descending), then cve_id, and add a unique 0-1 `score` in that order,
    so every writer sorts it the same way."""
    out = out.sort_values(
        [*keys, "cve_id"], ascending=[False] * len(keys) + [True], kind="mergesort"
    ).reset_index(drop=True)
    out["score"] = 1.0 - out.index / len(out)
    return out


def ensemble_scores(
    models: list[tuple], df: pd.DataFrame, features: list[str] = mf.FEATURES
) -> pd.DataFrame:
    """cve_id, rank_avg, mean_prob and score: a unique 0-1 score in final order (rank
    average, then mean probability, then cve_id)."""
    seed_scores = [predict(b, df, c, features) for _, b, c in models]
    out = rank_average(seed_scores).assign(cve_id=df["cve_id"].to_numpy())
    return ordered(out, ["rank_avg", "mean_prob"])[["cve_id", "score", "rank_avg", "mean_prob"]]


def submission_scores(models: list[tuple], df: pd.DataFrame, config: dict) -> pd.DataFrame:
    """The submitted ranking for df: the ensemble, rank-blended with the safety ranker when
    alpha < 1 (SHE-114). Columns cve_id, score (unique, in final order) and score_raw."""
    ens = ensemble_scores(models, df, config["features"])
    alpha = float(config.get("alpha", 1.0))
    if alpha >= 1.0:
        return ens.assign(score_raw=ens["rank_avg"])[["cve_id", "score", "score_raw"]]
    from backend.modeling.blend import blend

    model = ens.set_index("cve_id").loc[df["cve_id"], "rank_avg"].reset_index(drop=True)
    safety = pd.Series(safety_score(df.reset_index(drop=True)).to_numpy())
    out = pd.DataFrame(
        {"cve_id": df["cve_id"].to_numpy(), "score_raw": blend(model, safety, alpha).to_numpy()}
    )
    return ordered(out, ["score_raw"])[["cve_id", "score", "score_raw"]]


def reasons_for(
    models: list[tuple], df: pd.DataFrame, cwe_names: dict, features: list[str] = mf.FEATURES
) -> list[list[str]]:
    _, booster, categories = models[0]  # seed 0
    X, _ = mf.prepare(df, categories, features=features)
    return explain.top_reasons(booster, X, df.reset_index(drop=True), cwe_names=cwe_names)


def reason_kind(reason: str) -> str:
    """A reason with its row-specific values blanked, for counting the common ones."""
    if " has had " in reason:
        return "<assigner> has had N vulnerabilities added to KEV before"
    return re.sub(r"\d[\d,.]*", "N", reason)


def main() -> None:
    """SHE-58's model alone. Since SHE-116 the submission comes from
    `python -m backend.modeling.select` (see MODEL_CARD.md); this reproduces SHE-58."""
    con = connect()
    data = mf.load(con)
    params = load_params()
    config = {"variant": "lgbm_she8", "model": "lgbm_she8", "labels": "benchmark",
              "label_end": None, "alpha": 1.0, "features": mf.FEATURES, "params": params}  # fmt: skip
    publish(con, data, train_final(data, params), config, params)


def publish(con, data: pd.DataFrame, models: list[tuple], config: dict, params: dict) -> dict:
    """Save the final models with their config, write top500.csv through the validated
    writer and top500_reasons.csv (model part, seed-0 booster), and log a summary."""
    save_final(models, config)
    scoreboard = data[data["fold"] == SCORE_FOLD].reset_index(drop=True)
    scores = submission_scores(models, scoreboard, config)
    model_features = list(config["features"])
    if float(config.get("alpha", 1.0)) < 1.0:
        model_features += [c for c in safety.INPUTS if c not in model_features]
    summary = write_submission(con, scores, model_features=model_features)

    top = pick_top(scores)
    top_rows = scoreboard.set_index("cve_id").loc[top["cve_id"]].reset_index()
    reasons = reasons_for(models, top_rows, explain.load_cwe_names(con), config["features"])
    with (OUTPUTS_DIR / "top500_reasons.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["rank", "cve_id", "reason_1", "reason_2", "reason_3"])
        for rank, (cve, rs) in enumerate(zip(top["cve_id"], reasons, strict=True), 1):
            writer.writerow([rank, cve, *(rs + ["", "", ""])[:3]])

    safety_top = set(pick_top(safety.scores_2026(con))["cve_id"])
    common = Counter(reason_kind(r) for rs in reasons for r in rs)
    log = {
        "config": {k: v for k, v in config.items() if k != "features"},
        "params": params,
        "seeds": list(SEEDS),
        "train_folds": list(TRAIN_FOLDS),
        "train_rows": int(data["fold"].isin(TRAIN_FOLDS).sum()),
        "train_positives": int(data.loc[data["fold"].isin(TRAIN_FOLDS), "label"].sum()),
        "writer_summary": summary,
        "overlap_with_safety_top500": len(safety_top & set(top["cve_id"])),
        "with_exploit_code": round(summary["share_with_exploit_code"] * 500),
        "rows_with_no_reason": sum(1 for rs in reasons if not rs),
        "top_reasons": common.most_common(5),
        "top10": top["cve_id"].head(10).tolist(),
    }
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "final_log.json").write_text(json.dumps(log, indent=2) + "\n")
    print(json.dumps({k: v for k, v in log.items() if k != "params"}, indent=2))
    return log


if __name__ == "__main__":
    main()
