"""SHE-36: the README's three rankings, scored on both backtest folds.

Run after `uv run python -m backend.pipeline.features`:

    uv run python -m backend.modeling.baselines

Writes outputs/baselines.csv. These are the numbers every model has to beat.
"""

import csv

from backend.core.config import OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling.evaluate import evaluate, ranked_sql
from backend.pipeline.features import features_parquet
from backend.pipeline.population import HISTORY_FOLDS

# The README ranks by the raw CVSS 3 score, so the baseline does too (the model doesn't).
BASELINES = {
    "cvss_first": "raw_cvss3_score DESC NULLS LAST, epss DESC NULLS LAST",
    "epss_first": "epss DESC NULLS LAST",
    "exploit_then_epss": "any_exploit_code DESC, epss DESC NULLS LAST",
}


def baseline_source() -> str:
    return f"""(
        SELECT f.*, v.cvss3_score AS raw_cvss3_score
        FROM {features_parquet("features")} AS f
        JOIN vulnerabilities AS v ON v.cve_id = f.cve_id
    )"""


def run_baselines(con) -> list[dict]:
    results = []
    for fold in HISTORY_FOLDS:
        for name, order_by in BASELINES.items():
            result = evaluate(con, fold, ranked_sql(baseline_source(), fold, order_by))
            results.append({"ranking": name, **result})
    return results


def main() -> None:
    results = run_baselines(connect())
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUTS_DIR / "baselines.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    for r in results:
        print(
            f"{r['fold']}  {r['ranking']:<18} hits@{r['k']:<4} {r['hits_at_k']:>3}"
            f"   hits@500 {r['hits_at_500']:>3}   of {r['positives']}"
        )


if __name__ == "__main__":
    main()
