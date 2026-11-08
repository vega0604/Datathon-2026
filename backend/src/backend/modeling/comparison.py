"""SHE-111: one comparison table for every ranking, under one rule.

    uv run python -m backend.modeling.comparison

Writes the first rows of outputs/comparison.csv (README baselines, the safety ranker,
the SHE-8 LightGBM) and the SHE-112 rows (SHE-8 parameters trained on long labels), and
logs training positives per label mode to outputs/logs/labels_log.json. Later modules
(constrained, blend, logreg) add their rows with upsert().

Directions: "primary" trains on 2024 and tests on 2025 (hits@243); "time_reversed"
trains on 2025 and tests on 2024 (hits@198). Rankings that don't train (baselines,
safety) are just evaluated on each fold. A variant's primary score is its 2025 mean
hits@243 plus its time-reversed 2024 mean hits@198.
"""

import csv
import json

import pandas as pd

from backend.core.config import LOGS_DIR, OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling import features as mf
from backend.modeling.baselines import run_baselines
from backend.modeling.evaluate import evaluate_frame
from backend.modeling.labels import LABEL_ENDS, train_labels
from backend.modeling.safety import safety_score
from backend.modeling.train import load_params, run_protocol

COMPARISON = OUTPUTS_DIR / "comparison.csv"
DIRECTIONS = {"primary": 2025, "time_reversed": 2024}
CURRENT_SUBMISSION = ("lgbm_she8", "benchmark")  # variant and labels behind top500.csv
COLUMNS = [
    "variant", "labels", "direction", "test_fold", "k",
    "hits_at_k_mean", "hits_at_k_min", "hits_at_k_max",
    "hits_at_500_mean", "hits_at_500_min", "hits_at_500_max", "primary_score",
]  # fmt: skip


def single(result: dict) -> dict:
    """A deterministic result (one run) in the seed-summary shape."""
    return {
        "k": result["k"],
        "hits_at_k": {s: result["hits_at_k"] for s in ("mean", "min", "max")},
        "hits_at_500": {s: result["hits_at_500"] for s in ("mean", "min", "max")},
    }


def primary_score(results: dict[str, dict]) -> float:
    return results["primary"]["hits_at_k"]["mean"] + results["time_reversed"]["hits_at_k"]["mean"]


def rows_for(variant: str, labels: str, results: dict[str, dict]) -> list[dict]:
    """Comparison rows for one variant; results maps direction -> seed summary."""
    score = round(primary_score(results), 3)
    return [
        {
            "variant": variant,
            "labels": labels,
            "direction": direction,
            "test_fold": DIRECTIONS[direction],
            "k": r["k"],
            **{f"hits_at_k_{s}": r["hits_at_k"][s] for s in ("mean", "min", "max")},
            **{f"hits_at_500_{s}": r["hits_at_500"][s] for s in ("mean", "min", "max")},
            "primary_score": score,
        }
        for direction, r in results.items()
    ]


def read(path=COMPARISON) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def upsert(rows: list[dict], path=COMPARISON) -> None:
    """Replace rows with the same (variant, labels, direction), keep the rest in order."""
    existing = read(path)
    keys = {(r["variant"], r["labels"], r["direction"]): r for r in rows}
    merged, seen = [], set()
    for r in existing:
        key = (r["variant"], r["labels"], r["direction"])
        if key in keys:
            merged.append(keys[key])
            seen.add(key)
        else:
            merged.append(r)
    merged += [r for key, r in keys.items() if key not in seen]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(merged)


def baseline_rows(con) -> list[dict]:
    by_name: dict[str, dict] = {}
    for r in run_baselines(con):
        direction = "primary" if r["fold"] == 2025 else "time_reversed"
        by_name.setdefault(r["ranking"], {})[direction] = single(r)
    return [row for name, res in by_name.items() for row in rows_for(name, "none", res)]


def safety_results(con, data: pd.DataFrame) -> dict[str, dict]:
    results = {}
    for direction, fold in DIRECTIONS.items():
        part = data[data["fold"] == fold]
        scores = pd.DataFrame({"cve_id": part["cve_id"], "score": safety_score(part)})
        results[direction] = single(evaluate_frame(con, fold, scores))
    return results


def model_results(con, data, params, label_mode="benchmark", **kwargs) -> dict[str, dict]:
    return {
        direction: run_protocol(con, data, params, direction, label_mode, **kwargs)
        for direction in DIRECTIONS
    }


TRAINING_FOLDS = {"primary": (2024,), "time_reversed": (2025,), "final": (2024, 2025)}


def positives_log(con, data: pd.DataFrame) -> dict:
    """Training positives per fold: the benchmark label, and the long label of each run
    that trains on that fold."""
    log = {}
    for fold in (2024, 2025):
        part = data[data["fold"] == fold]
        log[str(fold)] = {"benchmark": int(part["label"].sum())}
        for run, end in LABEL_ENDS.items():
            if fold in TRAINING_FOLDS[run]:
                log[str(fold)][f"long_{run}_{end}"] = int(train_labels(con, part, end).sum())
    return log


def print_rows(rows: list[dict]) -> None:
    for r in rows:
        print(
            f"{r['variant']:<26} {r['labels']:<9} {r['direction']:<13} hits@{r['k']:<3} "
            f"{float(r['hits_at_k_mean']):5.1f} [{r['hits_at_k_min']}-{r['hits_at_k_max']}]  "
            f"hits@500 {float(r['hits_at_500_mean']):5.1f}  primary {float(r['primary_score']):5.1f}"
        )


def main() -> None:
    con = connect()
    data = mf.load(con, folds=(2024, 2025))
    params = load_params()
    if COMPARISON.exists():
        COMPARISON.unlink()  # this module starts the table; later modules add to it
    rows = baseline_rows(con)
    rows += rows_for("safety", "none", safety_results(con, data))
    rows += rows_for("lgbm_she8", "benchmark", model_results(con, data, params))
    rows += rows_for("lgbm_she8", "long", model_results(con, data, params, "long"))
    upsert(rows)
    positives = positives_log(con, data)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "labels_log.json").write_text(json.dumps(positives, indent=2) + "\n")
    print_rows(rows)
    print("\ntraining positives:", json.dumps(positives))


if __name__ == "__main__":
    main()
