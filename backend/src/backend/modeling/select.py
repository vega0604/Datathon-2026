"""SHE-116: pick the final ranking, and resubmit only on a clear win.

    uv run python -m backend.modeling.select

Reads outputs/comparison.csv and applies one rule against the current submission's row
(the SHE-8 LightGBM, benchmark labels). A variant clearly wins when
  - its primary score (2025 mean hits@243 + time-reversed 2024 mean hits@198) is at
    least 3 higher, and
  - it is not worse in either direction on its own (2025 hits@243 and 2024 hits@198 both
    at least the current submission's).
The best clear winner (highest primary score; the earlier table row on a tie) replaces
the submission: it is retrained on 2024 + 2025 (5 seeds, rank-averaged), blended with the
safety ranker if it is a blend, and written through the validated writer, with its
reasons and a rebuilt predictions.parquet. Writes outputs/selection.json.
"""

import argparse
import hashlib
import json

from backend.core.config import OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling import blend, comparison, serving
from backend.modeling import features as mf
from backend.modeling.constrained import PARAMS_PATH as CONSTRAINED_PATH
from backend.modeling.final import publish, train_final
from backend.modeling.labels import LABEL_ENDS
from backend.modeling.train import features_for, load_params, long_features

MARGIN = 3.0
SELECTION = OUTPUTS_DIR / "selection.json"


def summaries(rows: list[dict]) -> dict[tuple[str, str], dict]:
    """(variant, labels) -> primary score and each direction's mean hits@K, in table order."""
    out: dict[tuple[str, str], dict] = {}
    for r in rows:
        entry = out.setdefault(
            (r["variant"], r["labels"]), {"primary_score": float(r["primary_score"])}
        )
        entry[r["direction"]] = float(r["hits_at_k_mean"])
    return out


def check(candidate: dict, current: dict) -> dict:
    margin = candidate["primary_score"] - current["primary_score"]
    checks = {
        "margin": round(margin, 3),
        "margin_ok": margin >= MARGIN,
        "primary_ok": candidate["primary"] >= current["primary"],
        "time_reversed_ok": candidate["time_reversed"] >= current["time_reversed"],
    }
    checks["clearly_wins"] = (
        checks["margin_ok"] and checks["primary_ok"] and checks["time_reversed_ok"]
    )
    return checks


def decide(rows: list[dict], current_key=comparison.CURRENT_SUBMISSION) -> dict:
    table = summaries(rows)
    current = table[current_key]
    candidates = []
    for key, entry in table.items():
        if key == current_key:
            continue
        candidates.append({"variant": key[0], "labels": key[1], **entry, **check(entry, current)})
    winners = [c for c in candidates if c["clearly_wins"]]
    winner = max(winners, key=lambda c: c["primary_score"]) if winners else None  # first on ties
    return {
        "rule": f"primary score at least {MARGIN:g} higher and not worse in either direction",
        "current": {"variant": current_key[0], "labels": current_key[1], **current},
        "candidates": candidates,
        "winner": None
        if winner is None
        else {"variant": winner["variant"], "labels": winner["labels"]},
    }


def describe(decision: dict) -> str:
    cur = decision["current"]
    lines = [
        (
            f"current: {cur['variant']} ({cur['labels']}) primary {cur['primary_score']:.2f} "
            f"[2025 {cur['primary']:.2f}, 2024 {cur['time_reversed']:.2f}]"
        )
    ]
    for c in sorted(decision["candidates"], key=lambda c: -c["primary_score"]):
        flag = "CLEAR WIN" if c["clearly_wins"] else ""
        lines.append(
            f"  {c['variant']:<20} {c['labels']:<9} primary {c['primary_score']:6.2f} "
            f"({c['margin']:+.2f})  2025 {c['primary']:5.2f}  2024 {c['time_reversed']:5.2f}  {flag}"
        )
    w = decision["winner"]
    lines.append(
        f"decision: {w['variant']} ({w['labels']}) clearly wins"
        if w
        else "decision: nothing clearly wins"
    )
    return "\n".join(lines)


def winner_config(winner: dict) -> dict:
    """The final config (model, parameters, labels, features, blend weight) for a winning
    comparison row. Only tree-model variants and their blends can be retrained here."""
    variant, labels = winner["variant"], winner["labels"]
    if variant.startswith("blend_a"):
        model = blend.model_choice()
        name, labels, params = model["name"], model["labels"], model["params"]
        alpha = float(variant.removeprefix("blend_a"))
    elif variant == "lgbm_constrained":
        name, params = variant, json.loads(CONSTRAINED_PATH.read_text())[labels]["params"]
        alpha = 1.0
    elif variant == "lgbm_she8":
        name, params, alpha = variant, load_params(), 1.0
    else:
        raise NotImplementedError(f"no final retraining for {variant!r}")
    features = features_for(params)
    if labels == "long":
        features = long_features(features)
    return {
        "variant": variant,
        "model": name,
        "labels": labels,
        "label_end": LABEL_ENDS["final"] if labels == "long" else None,
        "alpha": alpha,
        "features": features,
        "params": params,
    }


def resubmit(con, config: dict) -> dict:
    """Retrain the winner on 2024 + 2025 (5 seeds, rank-averaged), write top500.csv and its
    reasons through final.publish, and rebuild predictions.parquet."""
    data = mf.load(con)
    models = train_final(
        data, config["params"], features=config["features"], label_end=config["label_end"],
        con=con,
    )  # fmt: skip
    log = publish(con, data, models, config, config["params"])
    serving.main()
    return log


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--decide-only", action="store_true", help="print and save the decision, change nothing"
    )
    args = parser.parse_args()
    decision = decide(comparison.read())
    if decision["winner"] and not args.decide_only:
        decision["final_config"] = winner_config(decision["winner"])
    SELECTION.parent.mkdir(parents=True, exist_ok=True)
    SELECTION.write_text(json.dumps(decision, indent=2) + "\n")
    print(describe(decision))
    if decision["winner"] and not args.decide_only:
        print("\nretraining the winner on 2024 + 2025 and writing top500.csv ...")
        resubmit(connect(), decision["final_config"])
        top = OUTPUTS_DIR / "top500.csv"
        print(f"top500.csv SHA-256 {hashlib.sha256(top.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
