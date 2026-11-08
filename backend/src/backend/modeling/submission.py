"""SHE-49: the only code that writes outputs/top500.csv.

    summary = write_submission(con, scores)   # scores: fold-2026 cve_id, score

Takes the 500 highest scores (ties by cve_id), checks them, and writes:
- outputs/top500.csv: exactly one column, cve_id, 500 rows (the submission);
- outputs/top500_scored.csv: rank, cve_id, score, snapshot_month, any_exploit_code and
  epss_pct, for review (gitignored).
"""

from pathlib import Path

import pandas as pd

from backend.core.config import OUTPUTS_DIR
from backend.modeling.evaluate import BENCHMARK_PICKS
from backend.pipeline.features import features_parquet


class SubmissionError(ValueError):
    pass


def pick_top(scores: pd.DataFrame, n: int = BENCHMARK_PICKS) -> pd.DataFrame:
    """The n best rows by score (descending, NULLs last), ties broken by cve_id."""
    ordered = scores.sort_values(
        ["score", "cve_id"], ascending=[False, True], na_position="last", kind="mergesort"
    )
    top = ordered.head(n).reset_index(drop=True)
    return top.assign(rank=range(1, len(top) + 1))


def validate(top: pd.DataFrame, scores: pd.DataFrame, scoreboard_ids: set[str]) -> None:
    problems = []
    if scores["cve_id"].duplicated().any():
        problems.append(f"{int(scores['cve_id'].duplicated().sum())} duplicate cve_ids in scores")
    if len(top) != BENCHMARK_PICKS:
        problems.append(f"{len(top)} rows, need exactly {BENCHMARK_PICKS}")
    if top["cve_id"].duplicated().any():
        problems.append("duplicate cve_ids in the top 500")
    outside = set(top["cve_id"]) - scoreboard_ids
    if outside:
        problems.append(f"{len(outside)} cve_ids not in scoreboard_2026, e.g. {min(outside)}")
    if top["score"].isna().any():
        problems.append(f"{int(top['score'].isna().sum())} NULL scores in the top 500")
    if problems:
        raise SubmissionError("top500 rejected: " + "; ".join(problems))


def write_submission(
    con,
    scores: pd.DataFrame,
    out_dir: Path = OUTPUTS_DIR,
    scoreboard: str = "scoreboard_2026",
    features: str | None = None,
) -> dict:
    """Validate and write the top 500; return a short summary of what was picked."""
    scoreboard_ids = {row[0] for row in con.execute(f"SELECT cve_id FROM {scoreboard}").fetchall()}
    top = pick_top(scores[["cve_id", "score"]])
    validate(top, scores, scoreboard_ids)

    cursor = con.cursor()
    try:
        cursor.register("_top", top)
        details = cursor.execute(
            f"""
            SELECT t.rank, t.cve_id, t.score, f.snapshot_month, f.any_exploit_code, f.epss_pct
            FROM _top AS t
            LEFT JOIN {features or features_parquet("features")} AS f
              ON f.cve_id = t.cve_id AND f.fold = 2026
            ORDER BY t.rank
            """
        ).df()
    finally:
        cursor.close()

    out_dir.mkdir(parents=True, exist_ok=True)
    top[["cve_id"]].to_csv(out_dir / "top500.csv", index=False, lineterminator="\n")
    details.to_csv(out_dir / "top500_scored.csv", index=False, lineterminator="\n")
    months = details["snapshot_month"].value_counts().sort_index()
    return {
        "rows": len(top),
        "share_with_exploit_code": round(float(details["any_exploit_code"].fillna(0).mean()), 4),
        "snapshot_months": {str(k): int(v) for k, v in months.items()},
        "min_epss_pct": (
            None if details["epss_pct"].isna().all() else float(details["epss_pct"].min())
        ),
        "null_epss_pct": int(details["epss_pct"].isna().sum()),
    }
