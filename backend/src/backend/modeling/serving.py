"""SHE-110: a score for every vulnerability, for the API.

    uv run python -m backend.modeling.serving   # after backend.modeling.final

Writes data/features/predictions.parquet: one row per cve_id in vulnerabilities, with
confidence, score_raw, score_pct (percentile within its confidence group), reasons (up
to 3) and as_of (the month of the signals used). Groups, in order of precedence:

1. exploited: on CISA KEV. Score 1; the reason says since when.
2. model: a fold-2026 scoreboard row. The final model's rank-averaged score and its
   SHAP reasons; as_of is the snapshot month.
3. lower: any other vulnerability with exploit signals. The safety-ranker formula at its
   latest signal month (assigner history as of that month's end, percentile within the
   month), with simple rule-based reasons.
4. no signal at all: lower, with a NULL score and no reasons.

2024 and 2025 backtest rows are deliberately not scored by the model: it was trained on
them, so their in-sample scores would look better than they are.
"""

import json

import numpy as np
import pandas as pd

from backend.core.config import FEATURES_DIR, LOGS_DIR
from backend.db.warehouse import connect
from backend.modeling import explain
from backend.modeling import features as mf
from backend.modeling.final import SCORE_FOLD, ensemble_scores, load_final_models, reasons_for
from backend.modeling.safety import safety_score
from backend.pipeline.features import add_assigner_history_sql

OUTPUT = FEATURES_DIR / "predictions.parquet"
COLUMNS = ["cve_id", "confidence", "score_raw", "score_pct", "reasons", "as_of"]
EPSS_REASON_PCT = 0.9  # rule-based reasons mention EPSS only in the top 10% of the month


def exploited_rows(con) -> pd.DataFrame:
    df = con.execute("SELECT cve_id, date_added FROM clean.kev ORDER BY cve_id").df()
    return pd.DataFrame(
        {
            "cve_id": df["cve_id"],
            "confidence": "exploited",
            "score_raw": 1.0,
            "reasons": [
                [f"On CISA's Known Exploited Vulnerabilities list since {d:%Y-%m-%d}"]
                for d in pd.to_datetime(df["date_added"])
            ],
            "as_of": pd.to_datetime(df["date_added"]).dt.strftime("%Y-%m"),
        }
    )


def model_rows(con, data: pd.DataFrame | None = None) -> pd.DataFrame:
    """The final model's scores and reasons for every scoreboard vulnerability."""
    if data is None:
        data = mf.load(con, folds=(SCORE_FOLD,))
    data = data.reset_index(drop=True)
    models = load_final_models()
    scores = ensemble_scores(models, data).set_index("cve_id")
    reasons = reasons_for(models, data, explain.load_cwe_names(con))
    return pd.DataFrame(
        {
            "cve_id": data["cve_id"],
            "confidence": "model",
            "score_raw": scores.loc[data["cve_id"], "rank_avg"].to_numpy(),
            "order": scores.loc[data["cve_id"], "score"].to_numpy(),
            "reasons": reasons,
            "as_of": data["snapshot_month"],
        }
    )


def latest_signals_sql(signals: str = "clean.exploit_signals") -> str:
    """Each vulnerability's signals at its latest month, with that month's last day."""
    return f"""
        SELECT s.cve_id, s.month, s.epss_pct, s.exploitdb, s.metasploit, s.nuclei,
               s.poc_github,
               greatest(s.exploitdb, s.metasploit, s.nuclei, s.poc_github) AS any_exploit_code,
               last_day(CAST(s.month || '-01' AS DATE)) AS snapshot_end
        FROM {signals} AS s
        JOIN (SELECT cve_id, max(month) AS month FROM {signals} GROUP BY cve_id) AS l
          ON l.cve_id = s.cve_id AND l.month = s.month
    """


def rule_reasons(row: dict) -> list[str]:
    reasons = [explain.render("exploit", row)]
    pct = row.get("epss_pct")
    if explain.present(pct) and pct >= EPSS_REASON_PCT:
        reasons.append(explain.render("epss", row))
    reasons.append(explain.render("assigner", row))
    return [r for r in reasons if r][:3]


def lower_rows(con, exclude: set[str]) -> pd.DataFrame:
    """Safety-ranker scores at the latest signal month for vulnerabilities outside KEV and
    the scoreboard."""
    df = con.execute(
        f"SELECT * FROM ({add_assigner_history_sql(f'({latest_signals_sql()})')})"
    ).df()
    df = df[~df["cve_id"].isin(exclude)].reset_index(drop=True)
    df["score_raw"] = safety_score(df.assign(fold=df["month"]))
    records = df.to_dict("records")
    return pd.DataFrame(
        {
            "cve_id": df["cve_id"],
            "confidence": "lower",
            "score_raw": df["score_raw"],
            "reasons": [rule_reasons(r) for r in records],
            "as_of": df["month"],
        }
    )


def unscored_rows(con, exclude: set[str]) -> pd.DataFrame:
    ids = [r[0] for r in con.execute("SELECT cve_id FROM vulnerabilities").fetchall()]
    ids = sorted(set(ids) - exclude)
    return pd.DataFrame(
        {"cve_id": ids, "confidence": "lower", "score_raw": np.nan,
         "reasons": [[] for _ in ids], "as_of": None}
    )  # fmt: skip


def group_percentiles(df: pd.DataFrame) -> pd.Series:
    """Percentile (0 to 1] of each score within its confidence group; ties share the top
    rank; NULL scores stay NULL. Model rows rank by their tie-broken final order."""
    key = df["order"].fillna(df["score_raw"]) if "order" in df else df["score_raw"]
    return key.groupby(df["confidence"]).rank(pct=True, method="max")


def combine(exploited, model, lower, unscored) -> pd.DataFrame:
    """Stack the groups in precedence order, keeping each cve_id's first (strongest) row."""
    out = pd.concat([exploited, model, lower, unscored], ignore_index=True)
    out = out.drop_duplicates("cve_id", keep="first").reset_index(drop=True)
    out["score_pct"] = group_percentiles(out)
    return out[COLUMNS].sort_values("cve_id").reset_index(drop=True)


def main() -> None:
    con = connect()
    exploited = exploited_rows(con)
    model = model_rows(con)
    taken = set(exploited["cve_id"]) | set(model["cve_id"])
    lower = lower_rows(con, taken)
    unscored = unscored_rows(con, taken | set(lower["cve_id"]))
    out = combine(exploited, model, lower, unscored)
    out.to_parquet(OUTPUT, index=False, compression="zstd")
    counts = out["confidence"].value_counts().to_dict()
    log = {
        "rows": len(out),
        "groups": {k: int(v) for k, v in counts.items()},
        "null_scores": int(out["score_raw"].isna().sum()),
        "no_reasons": int((out["reasons"].map(len) == 0).sum()),
    }
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "serving_log.json").write_text(json.dumps(log, indent=2) + "\n")
    print(json.dumps(log, indent=2))


if __name__ == "__main__":
    main()
