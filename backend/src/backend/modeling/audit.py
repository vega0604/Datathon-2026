"""SHE-54: prove the banned columns leak, with a deliberately "cheating" model.

    uv run python -m backend.pipeline.features --audit   # first: features_audit.parquet
    uv run python -m backend.modeling.audit

Same protocol and parameters as the real model (train 2024 -> test 2025, and the
time-reversed check), 5 seeds each:
  (a) clean: the whitelist;
  (b) cheater: the whitelist plus the leaky columns (NIST status, CPE and reference
      counts, NIST-supplied CVSS);
  (c) clean without kw_exploited, the suspect keyword.
Plus the share of positives and negatives that NIST had Analyzed, and the share of the
2026 scoreboard that is Analyzed. The cheater model is never used for a submission or
the API: write_submission refuses audit columns.

Writes outputs/leakage.csv (long format: table, name, fold, metric, value).
"""

import csv
import json

from backend.core.config import FEATURES_DIR, LOGS_DIR, OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling import features as mf
from backend.modeling.train import PROTOCOLS, backtest, load_params
from backend.pipeline.features import AUDIT_COLUMNS, features_parquet

MODELS = {
    "clean": list(mf.FEATURES),
    "cheater": [*mf.FEATURES, *AUDIT_COLUMNS],
    "clean_without_kw_exploited": [c for c in mf.FEATURES if c != "kw_exploited"],
}


def analyzed_shares(con) -> dict:
    """Share with nvd_status = 'Analyzed': positives vs negatives per backtest fold, and
    the whole 2026 scoreboard."""
    rows = con.execute(
        f"""
        SELECT fold,
               avg((nvd_status = 'Analyzed')::INT) FILTER (WHERE label = 1),
               avg((nvd_status = 'Analyzed')::INT) FILTER (WHERE label = 0),
               avg((nvd_status = 'Analyzed')::INT)
        FROM {features_parquet("features_audit")}
        GROUP BY fold ORDER BY fold
        """
    ).fetchall()
    shares = {}
    for fold, pos, neg, everyone in rows:
        if fold == 2026:
            shares["2026_all"] = everyone
        else:
            shares[f"{fold}_positives"] = pos
            shares[f"{fold}_negatives"] = neg
    return shares


def main() -> None:
    if not (FEATURES_DIR / "features_audit.parquet").exists():
        raise SystemExit("Run `uv run python -m backend.pipeline.features --audit` first.")
    con = connect()
    data = mf.load(con, folds=(2024, 2025), source=features_parquet("features_audit"))
    params = load_params()
    rows, summary = [], {}
    for model, columns in MODELS.items():
        for protocol, p in PROTOCOLS.items():
            r = backtest(con, data, params, p["train"], p["test"], features=columns)
            summary[f"{model}/{protocol}"] = r
            for metric in ("hits_at_k", "hits_at_500"):
                for stat in ("mean", "min", "max"):
                    rows.append(
                        {"table": "models", "name": f"{model}/{protocol}", "fold": p["test"],
                         "metric": f"{metric}_{stat}", "value": r[metric][stat]}
                    )  # fmt: skip
                rows.append(
                    {"table": "models", "name": f"{model}/{protocol}", "fold": p["test"],
                     "metric": f"{metric}_ensemble", "value": r["ensemble"][metric]}
                )  # fmt: skip
            print(
                f"{model:<28} {protocol:<14} hits@{r['k']} {r['hits_at_k']['mean']:>5.1f} "
                f"[{r['hits_at_k']['min']}-{r['hits_at_k']['max']}]   hits@500 "
                f"{r['hits_at_500']['mean']:>5.1f}",
                flush=True,
            )
    shares = analyzed_shares(con)
    for name, value in shares.items():
        fold, group = name.split("_", 1)
        rows.append(
            {"table": "analyzed_share", "name": group, "fold": int(fold),
             "metric": "share_analyzed", "value": value}
        )  # fmt: skip
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUTS_DIR / "leakage.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log = {
        "models": {
            k: {m: v[m] for m in ("hits_at_k", "hits_at_500", "ensemble", "k")}
            for k, v in summary.items()
        },
        "analyzed_share": shares,
    }
    (LOGS_DIR / "leakage_log.json").write_text(json.dumps(log, indent=2) + "\n")
    print("\nShare that NIST had Analyzed (nvd_status = 'Analyzed', as of today):")
    for fold in (2024, 2025):
        print(
            f"  {fold}: positives {shares[f'{fold}_positives']:.1%}, "
            f"negatives {shares[f'{fold}_negatives']:.1%}"
        )
    print(f"  2026 scoreboard: {shares['2026_all']:.1%}")


if __name__ == "__main__":
    main()
