"""SHE-110 (revised): one comparable score for every vulnerability, for the SBOM queue.

    uv run python -m backend.modeling.serving   # after backend.modeling.select (or final)

Writes data/features/predictions.parquet, one row per cve_id in vulnerabilities:

- exploited: on CISA KEV. score 1; reasons say since when (and ransomware use).
- model: every other vulnerability, scored by the submitted ranking (models/final/
  config.json: the final LightGBM, rank-blended with the safety ranker at its alpha):
    score = alpha * pct(p_exploit) + (1 - alpha) * pct(safety)
  with both percentiles taken over all non-KEV vulnerabilities, so any two scores compare.
  basis says which point in time the features describe:
    snapshot_2026   - a 2026 scoreboard row, at its snapshot month (as submitted);
    latest_signals  - its latest month in the 2024-25 signal files;
    no_signals      - never in the signal files: its publish month, or Dec 2025 if
                      older (no EPSS, exploit flags 0).
  Features are built with the same pipeline steps as training. Only vulnerabilities with
  a Granite embedding (the 2024-26 population and KEV) have KEV similarity; the rest are
  scored by a twin model trained without the similarity group (similarity_used = false).

p_exploit is the model's mean probability over its 5 seeds: unweighted training, so a rough
chance of a KEV addition within the label window, not a calibrated forecast. 2024-25
vulnerabilities were training rows at their publish month; here they are scored at their
latest month, a different snapshot, but their scores are still partly in-sample.

To refresh: load newer monthly signal files, rerun the pipeline (clean, features) and this.
"""

import json

import lightgbm as lgb
import numpy as np
import pandas as pd

from backend.core.config import FEATURES_DIR, LOGS_DIR
from backend.db.warehouse import connect
from backend.modeling import explain
from backend.modeling import features as mf
from backend.modeling.final import FINAL_DIR, final_config, load_final_models, train_final
from backend.modeling.safety import safety_score
from backend.modeling.train import SEEDS, save_models
from backend.modeling.train import score as predict
from backend.pipeline.features import FEATURE_STEPS, features_parquet
from backend.pipeline.similarity import kev_similarity, load_vectors

OUTPUT = FEATURES_DIR / "predictions.parquet"
EMBEDDINGS = FEATURES_DIR / "embeddings.parquet"
NOSIM_DIR = FINAL_DIR / "nosim"
SERVE_FOLD = 9999  # marks serving rows in the feature SQL; never a training fold
LATEST_HISTORY_MONTH = "2025-12"
COLUMNS = [
    "cve_id", "confidence", "basis", "score", "score_pct", "p_exploit", "model_pct",
    "safety_raw", "epss_pct", "any_exploit_code", "similarity_used", "reasons", "as_of",
]  # fmt: skip


# --- which rows, at which month ------------------------------------------------------------


def serve_rows_sql(signals: str = "clean.exploit_signals") -> str:
    """Every vulnerability not on KEV and not on the scoreboard, at its latest signal month
    (or its publish month / Dec 2025 when it has no signals), in the population layout the
    feature steps expect."""
    return f"""
        WITH latest AS (SELECT cve_id, max(month) AS month FROM {signals} GROUP BY cve_id),
        rows AS (
            SELECT v.cve_id, v.published,
                   coalesce(l.month, greatest(strftime(v.published, '%Y-%m'),
                                              '{LATEST_HISTORY_MONTH}')) AS snapshot_month,
                   l.month IS NOT NULL AS has_signals
            FROM vulnerabilities AS v
            LEFT JOIN latest AS l USING (cve_id)
            WHERE v.cve_id NOT IN (SELECT cve_id FROM scoreboard_2026)
              AND v.cve_id NOT IN (SELECT cve_id FROM clean.kev)
        ),
        dated AS (
            SELECT *, last_day(CAST(snapshot_month || '-01' AS DATE)) AS snapshot_end FROM rows
        )
        SELECT cve_id, {SERVE_FOLD} AS fold, published, snapshot_month,
               -- the next benchmark-style cutoff (Nov 4) on or after the snapshot
               make_date(year(snapshot_end) + CASE WHEN snapshot_end > make_date(
                   year(snapshot_end), 11, 4) THEN 1 ELSE 0 END, 11, 4) AS cutoff,
               snapshot_end, CAST(NULL AS UTINYINT) AS label, has_signals
        FROM dated
    """


def build_serve_features(con) -> pd.DataFrame:
    """The training feature steps (all but similarity) applied to the serving rows."""
    con.execute(f"CREATE OR REPLACE TEMP TABLE serve AS {serve_rows_sql()}")
    for name, step in FEATURE_STEPS:
        if name == "similarity":
            continue
        con.execute(f"CREATE OR REPLACE TEMP TABLE serve_next AS {step('serve')}")
        con.execute("DROP TABLE serve")
        con.execute("ALTER TABLE serve_next RENAME TO serve")
    return con.execute("SELECT * FROM serve ORDER BY cve_id").df()


def add_similarity(con, df: pd.DataFrame) -> pd.DataFrame:
    """kev_sim_max / kev_sim_top5 at each row's snapshot_end; NULL without an embedding."""
    if not EMBEDDINGS.exists():
        return df.assign(kev_sim_max=np.nan, kev_sim_top5=np.nan)
    kev = con.execute("SELECT cve_id, date_added FROM known_exploited").df()
    sims = kev_similarity(df[["cve_id", "fold", "snapshot_end"]], load_vectors(EMBEDDINGS), kev)
    return df.assign(
        kev_sim_max=sims["kev_sim_max"].to_numpy(), kev_sim_top5=sims["kev_sim_top5"].to_numpy()
    )


# --- models ----------------------------------------------------------------------------------


def nosim_models(con, config: dict) -> tuple[list[tuple], list[str]]:
    """The final model's twin without the similarity group, for rows with no embedding.
    Trained once with the same parameters, labels and seeds, and cached next to it."""
    features = [f for f in config["features"] if f not in mf.FEATURE_GROUPS["similarity"]]
    twin = {**config, "features": features}
    saved = NOSIM_DIR / "config.json"
    if saved.exists() and json.loads(saved.read_text()) == twin:
        categories = json.loads((NOSIM_DIR / "categories.json").read_text())
        return [
            (s, lgb.Booster(model_file=str(NOSIM_DIR / f"seed{s}.lgb")), categories) for s in SEEDS
        ], features
    data = mf.load(con, folds=(2024, 2025))
    models = train_final(
        data, config["params"], features=features, label_end=config.get("label_end"), con=con
    )
    save_models(models, NOSIM_DIR)
    saved.write_text(json.dumps(twin, indent=2) + "\n")
    return models, features


def mean_probability(models: list[tuple], df: pd.DataFrame, features: list[str]) -> np.ndarray:
    return np.mean([predict(b, df, c, features).to_numpy() for _, b, c in models], axis=0)


def contributions(models: list[tuple], df: pd.DataFrame, features: list[str]):
    """Seed-0 SHAP values (LightGBM's exact TreeSHAP) and the column names."""
    _, booster, categories = models[0]
    X, _ = mf.prepare(df, categories, features=features)
    return booster.predict(X, pred_contrib=True)[:, :-1], list(X.columns)


def pct(values: pd.Series) -> pd.Series:
    """Percentile rank in (0, 1]; ties share the top rank."""
    return values.rank(pct=True, method="max")


# --- assembly --------------------------------------------------------------------------------


def exploited_rows(con) -> pd.DataFrame:
    df = con.execute(
        "SELECT cve_id, date_added, known_ransomware_use FROM clean.kev ORDER BY cve_id"
    ).df()
    dates = pd.to_datetime(df["date_added"])
    reasons = []
    for d, ransomware in zip(dates, df["known_ransomware_use"], strict=True):
        r = [f"On CISA's Known Exploited Vulnerabilities list since {d:%Y-%m-%d}"]
        if ransomware == "Known":
            r.append("Known to be used in ransomware campaigns")
        reasons.append(r)
    return pd.DataFrame(
        {"cve_id": df["cve_id"], "confidence": "exploited", "basis": "kev", "score": 1.0,
         "score_pct": 1.0, "reasons": reasons, "as_of": dates.dt.strftime("%Y-%m")}
    )  # fmt: skip


def score_rows(con, rows: pd.DataFrame, config: dict) -> pd.DataFrame:
    """Model + safety blend for the non-KEV rows, with reasons from the model part."""
    rows = rows.reset_index(drop=True)
    has_sim = rows["kev_sim_max"].notna().to_numpy()
    sim_models, sim_features = load_final_models(), list(config["features"])
    twin_models, twin_features = nosim_models(con, config)
    p = np.full(len(rows), np.nan)
    reasons: list[list[str]] = [[] for _ in range(len(rows))]
    cwe_names = explain.load_cwe_names(con)
    for mask, models, features in (
        (has_sim, sim_models, sim_features),
        (~has_sim, twin_models, twin_features),
    ):
        part = rows[mask].reset_index(drop=True)
        if part.empty:
            continue
        p[mask] = mean_probability(models, part, features)
        contrib, names = contributions(models, part, features)
        part_reasons = explain.reasons_from_contributions(contrib, names, part, 3, cwe_names)
        for i, r in zip(np.flatnonzero(mask), part_reasons, strict=True):
            reasons[i] = r
    alpha = float(config.get("alpha", 1.0))
    safety = safety_score(rows)
    model_pct, safety_pct = pct(pd.Series(p)), pct(safety)
    score = alpha * model_pct + (1 - alpha) * safety_pct
    basis = np.where(
        rows["fold"] == 2026,
        "snapshot_2026",
        np.where(rows.get("has_signals", True).astype(bool), "latest_signals", "no_signals"),
    )
    return pd.DataFrame(
        {
            "cve_id": rows["cve_id"],
            "confidence": "model",
            "basis": basis,
            "score": score.to_numpy(),
            "score_pct": pct(score).to_numpy(),
            "p_exploit": p,
            "model_pct": model_pct.to_numpy(),
            "safety_raw": safety.to_numpy(),
            "epss_pct": rows["epss_pct"].to_numpy(),
            "any_exploit_code": rows["any_exploit_code"].astype(int).to_numpy(),
            "similarity_used": has_sim,
            "reasons": reasons,
            "as_of": rows["snapshot_month"].to_numpy(),
        }
    )


def combine(exploited: pd.DataFrame, scored: pd.DataFrame) -> pd.DataFrame:
    out = pd.concat([exploited, scored], ignore_index=True)
    out = out.drop_duplicates("cve_id", keep="first")  # KEV wins
    return out.reindex(columns=COLUMNS).sort_values("cve_id").reset_index(drop=True)


META = OUTPUT.with_name("predictions_meta.json")


def write_meta(out: pd.DataFrame, config: dict) -> dict:
    """What the API shows about the scores: which ranking, when built, how recent."""
    latest = out.loc[out["basis"] == "latest_signals", "as_of"]
    board = out.loc[out["basis"] == "snapshot_2026", "as_of"]
    meta = {
        "variant": config.get("variant"),
        "alpha": float(config.get("alpha", 1.0)),
        "built_at": pd.Timestamp.now(tz="UTC").isoformat(timespec="seconds"),
        "signals_through": None if latest.empty else str(latest.max()),
        "scoreboard_months": None if board.empty else [str(board.min()), str(board.max())],
        "refresh": "load newer signal files, rerun clean and features, then "
        "`uv run python -m backend.modeling.serving`",
    }
    META.write_text(json.dumps(meta, indent=2) + "\n")
    return meta


def main() -> None:
    con = connect()
    config = final_config()
    board = con.execute(f"SELECT * FROM {features_parquet('features')} WHERE fold = 2026").df()
    board = board.assign(has_signals=True)
    print("building features for the other vulnerabilities ...", flush=True)
    others = add_similarity(con, build_serve_features(con))
    rows = pd.concat([board, others], ignore_index=True)
    print(f"scoring {len(rows):,} vulnerabilities ...", flush=True)
    out = combine(exploited_rows(con), score_rows(con, rows, config))
    out.to_parquet(OUTPUT, index=False, compression="zstd")
    log = {
        "rows": len(out),
        "variant": config.get("variant"),
        "alpha": config.get("alpha"),
        "groups": {k: int(v) for k, v in out["confidence"].value_counts().items()},
        "basis": {k: int(v) for k, v in out["basis"].value_counts().items()},
        "similarity_used": int(out["similarity_used"].eq(True).sum()),
        "null_scores": int(out["score"].isna().sum()),
        "no_reasons": int((out["reasons"].map(len) == 0).sum()),
    }
    write_meta(out, config)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "serving_log.json").write_text(json.dumps(log, indent=2) + "\n")
    print(json.dumps(log, indent=2))


if __name__ == "__main__":
    main()
