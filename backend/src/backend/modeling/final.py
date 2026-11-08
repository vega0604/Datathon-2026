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
from backend.modeling.submission import pick_top, write_submission
from backend.modeling.train import MODELS_DIR, SEEDS, fit, load_params, rank_average, save_models
from backend.modeling.train import score as predict

FINAL_DIR = MODELS_DIR / "final"
TRAIN_FOLDS = (2024, 2025)
SCORE_FOLD = 2026


def train_final(data: pd.DataFrame, params: dict, seeds=SEEDS) -> list[tuple]:
    train_df = data[data["fold"].isin(TRAIN_FOLDS)]
    models = []
    for seed in seeds:
        booster, categories = fit(train_df, params, seed)
        models.append((seed, booster, categories))
    return models


def load_final_models() -> list[tuple]:
    categories = json.loads((FINAL_DIR / "categories.json").read_text())
    return [
        (seed, lgb.Booster(model_file=str(FINAL_DIR / f"seed{seed}.lgb")), categories)
        for seed in SEEDS
    ]


def ensemble_scores(models: list[tuple], df: pd.DataFrame) -> pd.DataFrame:
    """cve_id, rank_avg, mean_prob and score: a unique 0-1 score in final order (rank
    average, then mean probability, then cve_id), so every writer sorts it the same way."""
    seed_scores = [predict(booster, df, categories) for _, booster, categories in models]
    out = rank_average(seed_scores).assign(cve_id=df["cve_id"].to_numpy())
    out = out.sort_values(
        ["rank_avg", "mean_prob", "cve_id"], ascending=[False, False, True], kind="mergesort"
    ).reset_index(drop=True)
    out["score"] = 1.0 - out.index / len(out)
    return out[["cve_id", "score", "rank_avg", "mean_prob"]]


def reasons_for(models: list[tuple], df: pd.DataFrame, cwe_names: dict) -> list[list[str]]:
    _, booster, categories = models[0]  # seed 0
    X, _ = mf.prepare(df, categories)
    return explain.top_reasons(booster, X, df.reset_index(drop=True), cwe_names=cwe_names)


def reason_kind(reason: str) -> str:
    """A reason with its row-specific values blanked, for counting the common ones."""
    if " has had " in reason:
        return "<assigner> has had N vulnerabilities added to KEV before"
    return re.sub(r"\d[\d,.]*", "N", reason)


def main() -> None:
    con = connect()
    data = mf.load(con)
    params = load_params()
    models = train_final(data, params)
    save_models(models, FINAL_DIR)
    scoreboard = data[data["fold"] == SCORE_FOLD].reset_index(drop=True)
    scores = ensemble_scores(models, scoreboard)
    summary = write_submission(con, scores, model_features=mf.FEATURES)

    top = pick_top(scores)
    top_rows = scoreboard.set_index("cve_id").loc[top["cve_id"]].reset_index()
    reasons = reasons_for(models, top_rows, explain.load_cwe_names(con))
    with (OUTPUTS_DIR / "top500_reasons.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["rank", "cve_id", "reason_1", "reason_2", "reason_3"])
        for rank, (cve, rs) in enumerate(zip(top["cve_id"], reasons, strict=True), 1):
            writer.writerow([rank, cve, *(rs + ["", "", ""])[:3]])

    safety_top = set(pick_top(safety.scores_2026(con))["cve_id"])
    common = Counter(reason_kind(r) for rs in reasons for r in rs)
    log = {
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


if __name__ == "__main__":
    main()
