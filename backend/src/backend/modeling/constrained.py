"""SHE-113: monotone constraints and simpler trees.

    uv run python -m backend.modeling.constrained

Grid (24), every combination with max_depth 3 and monotone constraints (+1 on EPSS
percentile, exploit flags, assigner KEV history and KEV similarity): num_leaves {3, 5, 7}
x min_child_samples {100, 200} x n_estimators {400, 800} at learning_rate 0.02 x
feature_set {all, core}. Other settings come from params.json (SHE-52).

Run under both label modes with 3 seeds in both directions, picked by the primary score
(2025 mean hits@243 + time-reversed 2024 mean hits@198, ties to the simpler model). The
top 3 per label mode rerun with 5 seeds; the best per label mode goes to comparison.csv,
and its parameters to modeling/params_constrained.json.
"""

import csv
import itertools
import json
from pathlib import Path

from backend.core.config import OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling import comparison
from backend.modeling import features as mf
from backend.modeling.labels import LABEL_MODES
from backend.modeling.train import SEEDS, load_params

PARAMS_PATH = Path(__file__).with_name("params_constrained.json")
GRID_SEEDS = (0, 1, 2)
FINALISTS = 3
TUNED_KEYS = ("num_leaves", "min_child_samples", "n_estimators", "feature_set")


def grid(base: dict | None = None) -> list[dict]:
    base = base or load_params()
    return [
        {**base, "max_depth": 3, "learning_rate": 0.02, "monotone": True,
         "num_leaves": leaves, "min_child_samples": child, "n_estimators": trees,
         "feature_set": feature_set}
        for leaves, child, trees, feature_set in itertools.product(
            (3, 5, 7), (100, 200), (400, 800), ("all", "core")
        )
    ]  # fmt: skip


def simplicity(params: dict) -> tuple:
    """Smaller is simpler: fewer leaves, more samples per leaf, fewer trees, fewer
    features."""
    return (
        params["num_leaves"],
        -params["min_child_samples"],
        params["n_estimators"],
        len(mf.FEATURE_SETS[params["feature_set"]]),
    )


def ranked(entries: list[tuple[dict, float]]) -> list[tuple[dict, float]]:
    """(params, primary score) pairs, best first; ties to the simpler model."""
    return sorted(entries, key=lambda e: (-e[1], simplicity(e[0])))


def describe(params: dict) -> str:
    return ", ".join(f"{k}={params[k]}" for k in TUNED_KEYS)


def main() -> None:
    con = connect()
    data = mf.load(con, folds=(2024, 2025))
    log_rows, chosen = [], {}
    for label_mode in LABEL_MODES:
        entries = []
        for params in grid():
            results = comparison.model_results(con, data, params, label_mode, seeds=GRID_SEEDS)
            score = comparison.primary_score(results)
            entries.append((params, score))
            log_rows.append({"labels": label_mode, "seeds": len(GRID_SEEDS),
                             **{k: params[k] for k in TUNED_KEYS}, "primary_score": score})  # fmt: skip
            print(f"{label_mode:<9} {describe(params)}: {score:.2f}", flush=True)
        finals = []
        for params, _ in ranked(entries)[:FINALISTS]:
            results = comparison.model_results(con, data, params, label_mode, seeds=SEEDS)
            score = comparison.primary_score(results)
            finals.append((params, score, results))
            log_rows.append({"labels": label_mode, "seeds": len(SEEDS),
                             **{k: params[k] for k in TUNED_KEYS}, "primary_score": score})  # fmt: skip
        best_params, best_score = ranked([(p, s) for p, s, _ in finals])[0]
        best_results = next(r for p, s, r in finals if p is best_params)
        comparison.upsert(comparison.rows_for("lgbm_constrained", label_mode, best_results))
        chosen[label_mode] = {"params": best_params, "primary_score": best_score}
        print(f"best {label_mode}: {describe(best_params)} -> {best_score:.2f}", flush=True)
    best_mode = ranked([(v["params"], v["primary_score"]) for v in chosen.values()])[0][0]
    chosen["best"] = next(m for m, v in chosen.items() if v["params"] is best_mode)
    PARAMS_PATH.write_text(json.dumps(chosen, indent=2) + "\n")
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUTS_DIR / "constrained_grid.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(log_rows[0]))
        writer.writeheader()
        writer.writerows(log_rows)
    comparison.print_rows([r for r in comparison.read() if r["variant"] == "lgbm_constrained"])


if __name__ == "__main__":
    main()
