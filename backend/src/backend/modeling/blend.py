"""SHE-114: rank-blend the model with the safety ranker.

    uv run python -m backend.modeling.blend

    blend = alpha * pct_rank(model) + (1 - alpha) * pct_rank(safety)

with percentile ranks taken within the fold (ties by cve_id downstream, as usual).
alpha = 0 is the pure safety ranker, 1 the pure model. The model is the best SHE-113
constrained variant if its primary score beats the SHE-8 model, else the SHE-8 model.
alpha in {0, 0.25, 0.5, 0.75, 1} is chosen by the primary score (ties to the smaller
alpha, the more transparent ranking). Each seed's model scores are blended separately,
so results are a 5-seed mean, min and max like every other model row.
"""

import json

import pandas as pd

from backend.db.warehouse import connect
from backend.modeling import comparison
from backend.modeling import features as mf
from backend.modeling.constrained import PARAMS_PATH as CONSTRAINED_PATH
from backend.modeling.evaluate import evaluate_frame
from backend.modeling.safety import safety_score
from backend.modeling.train import load_params, summarise

ALPHAS = (0.0, 0.25, 0.5, 0.75, 1.0)


def pct_rank(scores: pd.Series) -> pd.Series:
    """Percentile rank within the series (ties share the average rank)."""
    return scores.rank(pct=True, method="average")


def blend(model_scores: pd.Series, safety_scores: pd.Series, alpha: float) -> pd.Series:
    return alpha * pct_rank(model_scores) + (1 - alpha) * pct_rank(safety_scores)


def model_choice() -> dict:
    """The model the blend uses: the best constrained variant if it beat SHE-8's model on
    the primary score, else SHE-8's (benchmark labels, params.json)."""
    rows = comparison.read()

    def score(variant, labels):
        return next(
            float(r["primary_score"])
            for r in rows
            if r["variant"] == variant and r["labels"] == labels
        )

    she8 = score("lgbm_she8", "benchmark")
    if CONSTRAINED_PATH.exists():
        chosen = json.loads(CONSTRAINED_PATH.read_text())
        mode = chosen["best"]
        constrained = score("lgbm_constrained", mode)
        if constrained > she8:
            return {"name": "lgbm_constrained", "labels": mode,
                    "params": chosen[mode]["params"], "primary_score": constrained}  # fmt: skip
    return {"name": "lgbm_she8", "labels": "benchmark", "params": load_params(),
            "primary_score": she8}  # fmt: skip


def blend_results(con, data: pd.DataFrame, model: dict) -> dict[float, dict[str, dict]]:
    """alpha -> direction -> seed summary."""
    out: dict[float, dict[str, dict]] = {a: {} for a in ALPHAS}
    for direction, fold in comparison.DIRECTIONS.items():
        r = comparison.run_protocol(
            con, data, model["params"], direction, model["labels"], keep_scores=True
        )
        ids, seed_scores = r["scores"]
        part = data[data["fold"] == fold].set_index("cve_id").loc[ids].reset_index()
        safety = pd.Series(safety_score(part).to_numpy())
        for alpha in ALPHAS:
            per_seed = [
                evaluate_frame(
                    con, fold,
                    pd.DataFrame({"cve_id": ids, "score": blend(s.reset_index(drop=True), safety, alpha)}),
                )
                for s in seed_scores
            ]  # fmt: skip
            out[alpha][direction] = {
                "k": per_seed[0]["k"],
                "hits_at_k": summarise([x["hits_at_k"] for x in per_seed]),
                "hits_at_500": summarise([x["hits_at_500"] for x in per_seed]),
            }
    return out


def choose_alpha(results: dict[float, dict[str, dict]]) -> float:
    return min(results, key=lambda a: (-comparison.primary_score(results[a]), a))


def main() -> None:
    con = connect()
    data = mf.load(con, folds=(2024, 2025))
    model = model_choice()
    print(f"model: {model['name']} ({model['labels']} labels), primary {model['primary_score']}")
    results = blend_results(con, data, model)
    rows = []
    for alpha, res in results.items():
        rows += comparison.rows_for(f"blend_a{alpha:g}", model["labels"], res)
    comparison.upsert(rows)
    best = choose_alpha(results)
    comparison.print_rows(rows)
    print(f"chosen alpha: {best:g} (primary {comparison.primary_score(results[best]):.2f})")


if __name__ == "__main__":
    main()
