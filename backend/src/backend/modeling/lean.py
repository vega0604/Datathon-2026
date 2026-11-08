"""Lean feature sets chosen from the univariate report (SHE-117), compared like every
other variant (SHE-111 rules).

    uv run python -m backend.modeling.lean

The selection rule is fixed before any backtest is run:
- the feature's auc_dir is at least 0.55 in every selection fold, with the same direction;
- at least 5 positives have a value in every selection fold (drops cvss4_score: 1 and 6);
- of each pair with |Spearman rho| >= 0.85, only the one with the higher mean auc_dir
  stays (whitelist order on a tie);
- numeric features are constrained monotone in their direction (+1 or -1); categorical
  ones are unconstrained.

Two variants, both with the SHE-113 constrained parameters (3 leaves, max_depth 3, 400
trees; no new tuning) and benchmark labels:
- lean_stable: selected on 2024 and 2025 together (the SHE-117 view). Its backtest is
  optimistic, because the selection saw the test year's labels.
- lean_nested: selected on the training fold only (2024 for train 2024 -> test 2025,
  2025 for the time-reversed check), so the test year never influences the features.
Each is also rank-blended with the safety ranker for alpha in {0.25, 0.5, 0.75, 1}.
All rows go to comparison.csv; the sets and directions to modeling/lean_features.json.
"""

import json
import math
from pathlib import Path

import pandas as pd

from backend.db.warehouse import connect
from backend.modeling import comparison
from backend.modeling import feature_report as fr
from backend.modeling import features as mf
from backend.modeling.blend import blend, choose_alpha
from backend.modeling.constrained import PARAMS_PATH as CONSTRAINED_PATH
from backend.modeling.evaluate import evaluate_frame
from backend.modeling.safety import safety_score
from backend.modeling.train import SEEDS, run_protocol, summarise

MIN_AUC = 0.55
MIN_POSITIVES_PRESENT = 5
REDUNDANT_RHO = 0.85
BLEND_ALPHAS = (0.25, 0.5, 0.75, 1.0)
LEAN_PATH = Path(__file__).with_name("lean_features.json")
TRAIN_FOLD = {"primary": 2024, "time_reversed": 2025}


# --- per-fold statistics ----------------------------------------------------------------


def category_scores(values: pd.Series, rate_values: pd.Series, rate_labels: pd.Series) -> pd.Series:
    """Each row's category KEV rate, measured on (rate_values, rate_labels)."""
    return fr.cross_fold_scores(values, rate_values, rate_labels)


def fold_values(data: pd.DataFrame, fold: int, feature: str) -> pd.Series:
    values = fr.category_values(data.loc[data["fold"] == fold, feature])
    return fr.collapse_cwe(values) if feature == "cwe_primary" else values


def feature_stats(data: pd.DataFrame, fold: int, rate_fold: int) -> dict[str, dict]:
    """auc_dir, direction and positives with a value, per feature, on one fold.
    Categorical features are scored with category KEV rates from rate_fold."""
    part = data[data["fold"] == fold]
    labels = part["label"].astype(int)
    stats = {}
    for feature in mf.FEATURES:
        if feature in mf.CATEGORICAL:
            values = fold_values(data, fold, feature)
            rate_labels = data.loc[data["fold"] == rate_fold, "label"]
            score = category_scores(values, fold_values(data, rate_fold, feature), rate_labels)
            present = values != fr.MISSING
        else:
            score = part[feature]
            present = score.notna()
        stats[feature] = {
            **fr.auc_direction(score, labels),
            "positives_present": int(labels[present].sum()),
        }
    return stats


# --- the selection rule (pure, unit-tested) ------------------------------------------------


def passes(per_fold: list[dict]) -> bool:
    directions = {s["direction"] for s in per_fold}
    return (
        None not in directions
        and len(directions) == 1
        and all(not math.isnan(s["auc_dir"]) and s["auc_dir"] >= MIN_AUC for s in per_fold)
        and all(s["positives_present"] >= MIN_POSITIVES_PRESENT for s in per_fold)
    )


def select_features(
    stats_by_fold: dict[int, dict[str, dict]], numeric_rows: pd.DataFrame
) -> tuple[list[str], dict[str, int]]:
    """The lean feature list (whitelist order) and its monotone directions."""
    folds = list(stats_by_fold)
    kept = [f for f in mf.FEATURES if passes([stats_by_fold[k][f] for k in folds])]
    mean_auc = {f: sum(stats_by_fold[k][f]["auc_dir"] for k in folds) / len(folds) for f in kept}
    numeric = [f for f in kept if f not in mf.CATEGORICAL]
    for pair in fr.redundant_pairs(numeric_rows[numeric].astype(float), REDUNDANT_RHO):
        a, b = pair["feature_a"], pair["feature_b"]
        if a in kept and b in kept:
            # keep the stronger; on a tie keep the earlier in the whitelist
            drop = b if mean_auc[a] >= mean_auc[b] else a
            kept.remove(drop)
    directions = {
        f: (1 if stats_by_fold[folds[0]][f]["direction"] == "+" else -1)
        for f in kept
        if f not in mf.CATEGORICAL
    }
    return kept, directions


def lean_params(base: dict, directions: dict[str, int]) -> dict:
    params = {k: v for k, v in base.items() if k != "feature_set"}
    return {**params, "monotone": True, "monotone_map": directions}


# --- variants ------------------------------------------------------------------------------


def selections(data: pd.DataFrame) -> dict:
    """lean_stable (both folds) and lean_nested (the training fold of each direction)."""
    both = {2024: feature_stats(data, 2024, 2025), 2025: feature_stats(data, 2025, 2024)}
    stable = select_features(both, data[data["fold"].isin(TRAIN_FOLD.values())])
    nested = {}
    for direction, fold in TRAIN_FOLD.items():
        one = {fold: feature_stats(data, fold, fold)}  # categories rated in-fold: train fold only
        nested[direction] = select_features(one, data[data["fold"] == fold])
    return {
        "lean_stable": {d: stable for d in TRAIN_FOLD},
        "lean_nested": nested,
    }


def variant_results(con, data, base: dict, by_direction: dict) -> dict[float, dict[str, dict]]:
    """alpha -> direction -> 5-seed summary; alpha 1 is the lean model alone."""
    out: dict[float, dict[str, dict]] = {a: {} for a in BLEND_ALPHAS}
    for direction, fold in comparison.DIRECTIONS.items():
        features, directions = by_direction[direction]
        r = run_protocol(
            con, data, lean_params(base, directions), direction, "benchmark",
            features=features, seeds=SEEDS, keep_scores=True,
        )  # fmt: skip
        ids, seed_scores = r["scores"]
        part = data[data["fold"] == fold].set_index("cve_id").loc[ids].reset_index()
        safety = pd.Series(safety_score(part).to_numpy())
        for alpha in BLEND_ALPHAS:
            per_seed = [
                evaluate_frame(con, fold, pd.DataFrame(
                    {"cve_id": ids, "score": blend(s.reset_index(drop=True), safety, alpha)}
                ))
                for s in seed_scores
            ]  # fmt: skip
            out[alpha][direction] = {
                "k": per_seed[0]["k"],
                "hits_at_k": summarise([x["hits_at_k"] for x in per_seed]),
                "hits_at_500": summarise([x["hits_at_500"] for x in per_seed]),
            }
    return out


def row_name(variant: str, alpha: float) -> str:
    return variant if alpha == 1.0 else f"blend_{variant}_a{alpha:g}"


def main() -> None:
    con = connect()
    data = mf.load(con, folds=(2024, 2025))
    base = json.loads(CONSTRAINED_PATH.read_text())["benchmark"]["params"]
    chosen = selections(data)
    saved = {"rule": __doc__.split("The selection rule is fixed before any backtest is run:")[1]
             .split("Two variants")[0].strip(), "base_params": base, "variants": {}}  # fmt: skip
    for variant, by_direction in chosen.items():
        results = variant_results(con, data, base, by_direction)
        rows = []
        for alpha, res in results.items():
            rows += comparison.rows_for(row_name(variant, alpha), "benchmark", res)
        comparison.upsert(rows)
        best = choose_alpha(results)
        saved["variants"][variant] = {
            direction: {"features": f, "directions": d}
            for direction, (f, d) in by_direction.items()
        }
        saved["variants"][variant]["best_alpha"] = best
        comparison.print_rows(rows)
        print(
            f"{variant}: best alpha {best:g}, primary {comparison.primary_score(results[best]):.2f}"
        )
    LEAN_PATH.write_text(json.dumps(saved, indent=2) + "\n")
    for variant, by_direction in saved["variants"].items():
        for direction in TRAIN_FOLD:
            feats = by_direction[direction]["features"]
            print(f"{variant} / {direction}: {len(feats)} features: {', '.join(feats)}")


if __name__ == "__main__":
    main()
