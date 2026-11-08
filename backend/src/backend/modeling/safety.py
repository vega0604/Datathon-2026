"""SHE-48: a transparent, model-free ranking. It is the fallback submission, the bar the
LightGBM model must clear, and the score for vulnerabilities the model doesn't cover.

    score = epss_pct + W_CODE * any_exploit_code + W_VENDOR * assigner_pct

epss_pct is the EPSS percentile in the snapshot month (NULL counts as 0); assigner_pct is
the percentile of assigner_kev_prior within the fold. The weights were picked on fold 2024
only and then reported on 2025:

    uv run python -m backend.modeling.safety            # grid on 2024, report 2025
    uv run python -m backend.modeling.safety --submit   # also write top500.csv for 2026
"""

import argparse
import csv
import itertools
import json

import pandas as pd

from backend.core.config import LOGS_DIR, OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling.evaluate import evaluate_frame
from backend.pipeline.features import features_parquet

W_CODE_GRID = (0.5, 1.0, 2.0)
W_VENDOR_GRID = (0.0, 0.25, 0.5, 1.0)
SELECTION_FOLD = 2024
REPORT_FOLD = 2025
# Chosen on fold 2024 (hits@198, then hits@500; grid order breaks ties), see
# outputs/logs/safety_log.json: 2024 hits@198 = 5, hits@500 = 10 (tied with w_code 2.0).
# Reported on 2025 afterwards, not used to choose: hits@243 = 13, hits@500 = 17.
W_CODE = 1.0
W_VENDOR = 0.0
INPUTS = ["epss_pct", "any_exploit_code", "assigner_kev_prior"]


def assigner_pct(kev_prior: pd.Series, group: pd.Series) -> pd.Series:
    """Percentile (0 to 1, like SQL percent_rank) of assigner_kev_prior within each group."""
    ranks = kev_prior.groupby(group).rank(method="min")
    sizes = kev_prior.groupby(group).transform("size")
    return ((ranks - 1) / (sizes - 1).where(sizes > 1)).fillna(0.0)


def safety_score(df: pd.DataFrame, w_code: float = W_CODE, w_vendor: float = W_VENDOR) -> pd.Series:
    """df needs epss_pct, any_exploit_code, assigner_kev_prior and fold."""
    return (
        df["epss_pct"].fillna(0.0)
        + w_code * df["any_exploit_code"].astype(float)
        + w_vendor * assigner_pct(df["assigner_kev_prior"].astype(float), df["fold"])
    )


def load(con, folds: tuple[int, ...]) -> pd.DataFrame:
    fold_list = ", ".join(str(f) for f in folds)
    return con.execute(
        f"""
        SELECT cve_id, fold, label, {", ".join(INPUTS)}
        FROM {features_parquet("features")} WHERE fold IN ({fold_list})
        """
    ).df()


def run_grid(con) -> list[dict]:
    df = load(con, (SELECTION_FOLD, REPORT_FOLD))
    results = []
    for w_code, w_vendor in itertools.product(W_CODE_GRID, W_VENDOR_GRID):
        scored = df.assign(score=safety_score(df, w_code, w_vendor))
        for fold in (SELECTION_FOLD, REPORT_FOLD):
            part = scored.loc[scored["fold"] == fold, ["cve_id", "score"]]
            r = evaluate_frame(con, fold, part)
            results.append({"w_code": w_code, "w_vendor": w_vendor, **r})
    return results


def choose(results: list[dict]) -> dict:
    """Best on the selection fold by hits@K, then hits@500; grid order breaks any tie."""
    selection = [r for r in results if r["fold"] == SELECTION_FOLD]
    return max(selection, key=lambda r: (r["hits_at_k"], r["hits_at_500"]))


def write_csv(rows: list[dict], name: str) -> None:
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUTS_DIR / name).open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submit", action="store_true", help="write top500.csv for 2026")
    args = parser.parse_args()
    con = connect()
    results = run_grid(con)
    write_csv(results, "safety.csv")
    best = choose(results)
    report = next(
        r
        for r in results
        if r["fold"] == REPORT_FOLD
        and (r["w_code"], r["w_vendor"]) == (best["w_code"], best["w_vendor"])
    )
    print(f"{'w_code':>6} {'w_vendor':>8}  2024 @198/@500   2025 @243/@500")
    for w_code, w_vendor in itertools.product(W_CODE_GRID, W_VENDOR_GRID):
        a, b = (
            next(
                r
                for r in results
                if r["fold"] == fold and (r["w_code"], r["w_vendor"]) == (w_code, w_vendor)
            )
            for fold in (SELECTION_FOLD, REPORT_FOLD)
        )
        print(
            f"{w_code:>6} {w_vendor:>8}  {a['hits_at_k']:>6}/{a['hits_at_500']:<6}"
            f"   {b['hits_at_k']:>6}/{b['hits_at_500']:<4}"
        )
    log = {
        "chosen": {"w_code": best["w_code"], "w_vendor": best["w_vendor"]},
        "module_constants": {"w_code": W_CODE, "w_vendor": W_VENDOR},
        "fold_2024": {k: best[k] for k in ("k", "hits_at_k", "hits_at_500", "positives")},
        "fold_2025": {k: report[k] for k in ("k", "hits_at_k", "hits_at_500", "positives")},
        "beats_exploit_then_epss_2025": report["hits_at_k"] > 13,
    }
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "safety_log.json").write_text(json.dumps(log, indent=2) + "\n")
    print(f"\nchosen on 2024: w_code={best['w_code']}, w_vendor={best['w_vendor']}")
    print(f"2024 hits@{best['k']} {best['hits_at_k']}, hits@500 {best['hits_at_500']}")
    print(f"2025 hits@{report['k']} {report['hits_at_k']}, hits@500 {report['hits_at_500']}")
    if (best["w_code"], best["w_vendor"]) != (W_CODE, W_VENDOR):
        print("NOTE: module constants differ from the grid choice; update W_CODE/W_VENDOR.")
    if args.submit:
        print(json.dumps(submit(con), indent=2))


def scores_2026(con) -> pd.DataFrame:
    """Safety scores for every fold-2026 (scoreboard) vulnerability."""
    df = load(con, (2026,))
    return df.assign(score=safety_score(df))[["cve_id", "score"]]


def submit(con) -> dict:
    """SHE-50: the fallback submission, written through the validated writer."""
    from backend.modeling.submission import write_submission

    return write_submission(con, scores_2026(con), model_features=INPUTS)


if __name__ == "__main__":
    main()
