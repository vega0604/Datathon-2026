"""SHE-52: a small LightGBM grid, chosen by a rule that doesn't trust 2025 alone.

    uv run python -m backend.modeling.tune

Grid (54): num_leaves {7, 15, 31} x min_child_samples {20, 50, 100} x learning_rate
{0.03 with 600 trees, 0.1 with 200} x max_pos_weight {1, 10, 200}. The spec's grid has
18 combinations with the class-weight cap fixed at 200; the cap was added because at
200 the model overfit the 27 training positives (SHE-51).

Every combination runs the primary backtest (train 2024, test 2025) with 3 seeds. The
top 3 by mean 2025 hits@243 also run the time-reversed check (train 2025, test 2024).
The pick maximises 2025 mean hits@243 + time-reversed 2024 mean hits@198; ties go to the
simpler model. Writes outputs/tuning.csv and modeling/params.json (committed: the source
of truth for final scoring).
"""

import csv
import itertools
import json

from backend.core.config import OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling import features as mf
from backend.modeling.train import DEFAULT_PARAMS, PARAMS_PATH, PROTOCOLS, backtest

TUNE_SEEDS = (0, 1, 2)
FINALISTS = 3
NUM_LEAVES = (7, 15, 31)
MIN_CHILD_SAMPLES = (20, 50, 100)
RATES = ((0.03, 600), (0.1, 200))  # (learning_rate, n_estimators)
MAX_POS_WEIGHTS = (1, 10, 200)
TUNED_KEYS = ("num_leaves", "min_child_samples", "learning_rate", "n_estimators", "max_pos_weight")


def grid() -> list[dict]:
    return [
        {**DEFAULT_PARAMS, "num_leaves": leaves, "min_child_samples": child,
         "learning_rate": rate, "n_estimators": trees, "max_pos_weight": cap}
        for leaves, child, (rate, trees), cap in itertools.product(
            NUM_LEAVES, MIN_CHILD_SAMPLES, RATES, MAX_POS_WEIGHTS
        )
    ]  # fmt: skip


def simplicity(params: dict) -> tuple:
    """Smaller is simpler: fewer leaves, more samples per leaf, fewer trees, less
    reweighting of positives."""
    return (
        params["num_leaves"],
        -params["min_child_samples"],
        params["n_estimators"],
        params["max_pos_weight"],
    )


def finalists(rows: list[dict], n: int = FINALISTS) -> list[dict]:
    """Top n by primary mean hits@K, then mean hits@500, then simplicity."""
    return sorted(
        rows, key=lambda r: (-r["primary_hits_at_k"], -r["primary_hits_at_500"], simplicity(r))
    )[:n]


def pick(rows: list[dict]) -> dict:
    """Among rows with a time-reversed result: highest primary + reversed mean hits@K,
    ties to the simpler model."""
    checked = [r for r in rows if r.get("reversed_hits_at_k") is not None]
    return min(
        checked,
        key=lambda r: (-(r["primary_hits_at_k"] + r["reversed_hits_at_k"]), simplicity(r)),
    )


def main() -> None:
    con = connect()
    data = mf.load(con, folds=(2024, 2025))
    rows = []
    combos = grid()
    for i, params in enumerate(combos, 1):
        p = PROTOCOLS["primary"]
        r = backtest(con, data, params, p["train"], p["test"], seeds=TUNE_SEEDS)
        rows.append(
            {
                **{k: params[k] for k in TUNED_KEYS},
                "primary_hits_at_k": r["hits_at_k"]["mean"],
                "primary_hits_at_500": r["hits_at_500"]["mean"],
                "primary_min_max": f"{r['hits_at_k']['min']}-{r['hits_at_k']['max']}",
                "reversed_hits_at_k": None,
                "reversed_hits_at_500": None,
            }
        )
        print(
            f"{i:>2}/{len(combos)} {params['num_leaves']:>2} leaves, min_child "
            f"{params['min_child_samples']:>3}, lr {params['learning_rate']}, cap "
            f"{params['max_pos_weight']:>3}: 2025 hits@243 {r['hits_at_k']['mean']:.2f}",
            flush=True,
        )
    for row in finalists(rows):
        params = {**DEFAULT_PARAMS, **{k: row[k] for k in TUNED_KEYS}}
        p = PROTOCOLS["time_reversed"]
        r = backtest(con, data, params, p["train"], p["test"], seeds=TUNE_SEEDS)
        row["reversed_hits_at_k"] = r["hits_at_k"]["mean"]
        row["reversed_hits_at_500"] = r["hits_at_500"]["mean"]
    best = pick(rows)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUTS_DIR / "tuning.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    chosen = {**DEFAULT_PARAMS, **{k: best[k] for k in TUNED_KEYS}}
    PARAMS_PATH.write_text(json.dumps(chosen, indent=2) + "\n")
    print("\nfinalists (primary 2025 @243 + time-reversed 2024 @198):")
    for row in finalists(rows):
        print(
            f"  {[row[k] for k in TUNED_KEYS]}: {row['primary_hits_at_k']:.2f} + "
            f"{row['reversed_hits_at_k']:.2f}"
        )
    print(f"chosen: {json.dumps({k: best[k] for k in TUNED_KEYS})}")


if __name__ == "__main__":
    main()
