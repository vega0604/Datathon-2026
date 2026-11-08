"""SHE-110 (revised): one comparable score for every vulnerability, for the SBOM queue.

    uv run python -m backend.modeling.serving   # after backend.modeling.select (or final)

Writes data/features/predictions.parquet, one row per cve_id in vulnerabilities:

- exploited: on CISA KEV. score 1 and as_of the month it was added; it is still run through
  the model so its reason bars explain what the model sees.
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

reasons are up to 3 bars {kind: exploit|exposure|vendor, label (< 45 chars), value (summed
SHAP contribution, log-odds)}. signal is the first warning sign that applies at as_of:
exploit_code, vendor_attacked or score_jump (see warning_signals).

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
    "safety_raw", "epss_pct", "any_exploit_code", "similarity_used", "reasons", "signal",
    "as_of",
]  # fmt: skip
# Warning signs, checked in this order (the first that applies is sent).
SIGNAL_WINDOW_DAYS = 30
EPSS_JUMP = 0.1


# --- which rows, at which month ------------------------------------------------------------


def serve_rows_sql(signals: str = "clean.exploit_signals") -> str:
    """Every vulnerability not on the scoreboard, at its latest signal month (or its publish
    month / Dec 2025 when it has no signals), in the population layout the feature steps
    expect. KEV entries are included so their reason bars come from the model too; their
    score is then set to 1."""
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


def kev_dates(con) -> pd.DataFrame:
    return con.execute("SELECT cve_id, date_added FROM clean.kev ORDER BY cve_id").df()


def warning_signals(con, rows: pd.DataFrame) -> list[str | None]:
    """The first warning sign that applies to each row, as of its snapshot month:
    exploit_code    - public exploit code appeared that month (absent the month before);
    vendor_attacked - another vulnerability in one of the same vulnerable products (NIST's
                      product lists) was added to KEV in the 30 days up to the snapshot's
                      end. Same-vendor alone fires for 40% of CVEs (big vendors get a KEV
                      entry most months), so the product must match;
    score_jump      - EPSS rose by 0.1 or more since the month before."""
    frame = pd.DataFrame(
        {
            "_i": range(len(rows)),
            "cve_id": rows["cve_id"].to_numpy(),
            "month": rows["snapshot_month"].to_numpy(),
            "snapshot_end": pd.to_datetime(rows["snapshot_end"]).to_numpy(),
            "code": rows["any_exploit_code"].fillna(0).astype(int).to_numpy(),
            "epss": rows["epss"].to_numpy(),
            "assigner": rows["assigner"].to_numpy(),
        }
    )
    cur = con.cursor()
    try:
        cur.register("_sig_rows", frame)
        out = cur.execute(
            f"""
            WITH f AS (
                SELECT *, strftime(CAST(month || '-01' AS DATE) - INTERVAL 1 MONTH, '%Y-%m')
                          AS prev_month
                FROM _sig_rows
            ),
            prev AS (
                SELECT s.cve_id, s.month, s.epss,
                       greatest(s.exploitdb, s.metasploit, s.nuclei, s.poc_github) AS code
                FROM clean.exploit_signals AS s
                SEMI JOIN f ON f.cve_id = s.cve_id AND f.prev_month = s.month
            ),
            products AS (
                SELECT DISTINCT cve_id, vendor_key, lower(product) AS product
                FROM clean.affected_products WHERE vulnerable = 'Y'
            ),
            kev_products AS (
                SELECT p.vendor_key, p.product, k.cve_id AS kev_cve, k.date_added
                FROM known_exploited AS k JOIN products AS p USING (cve_id)
            ),
            attacked AS (
                -- another CVE sharing a vulnerable product went onto KEV in the window
                SELECT DISTINCT f._i
                FROM f
                JOIN products AS p ON p.cve_id = f.cve_id
                JOIN kev_products AS kp
                  ON kp.vendor_key = p.vendor_key AND kp.product = p.product
                 AND kp.kev_cve <> f.cve_id
                 AND kp.date_added > CAST(f.snapshot_end AS DATE) - INTERVAL {SIGNAL_WINDOW_DAYS} DAY
                 AND kp.date_added <= CAST(f.snapshot_end AS DATE)
            )
            SELECT f._i,
                   f.code = 1 AND coalesce(p.code, 0) = 0 AS new_code,
                   a._i IS NOT NULL AS vendor,
                   coalesce(f.epss - p.epss >= {EPSS_JUMP}, false) AS jump
            FROM f
            LEFT JOIN prev AS p ON p.cve_id = f.cve_id AND p.month = f.prev_month
            LEFT JOIN attacked AS a ON a._i = f._i
            ORDER BY f._i
            """
        ).fetchall()
    finally:
        cur.close()
    signals: list[str | None] = []
    for _, new_code, vendor, jump in out:
        signals.append(
            "exploit_code" if new_code else "vendor_attacked" if vendor else
            "score_jump" if jump else None
        )  # fmt: skip
    return signals


def score_rows(
    con, rows: pd.DataFrame, config: dict, kev_ids: set[str] = frozenset()
) -> pd.DataFrame:
    """Model + safety blend for every row, with reason bars from the model part. Percentiles
    are taken over the non-KEV rows (KEV rows are set to 1 afterwards by apply_kev)."""
    rows = rows.reset_index(drop=True)
    has_sim = rows["kev_sim_max"].notna().to_numpy()
    sim_models, sim_features = load_final_models(), list(config["features"])
    twin_models, twin_features = nosim_models(con, config)
    p = np.full(len(rows), np.nan)
    reasons: list[list[dict]] = [[] for _ in range(len(rows))]
    cwe_names = explain.load_cwe_names(con)
    org_names = explain.load_org_names(con)
    for mask, models, features in (
        (has_sim, sim_models, sim_features),
        (~has_sim, twin_models, twin_features),
    ):
        part = rows[mask].reset_index(drop=True)
        if part.empty:
            continue
        p[mask] = mean_probability(models, part, features)
        contrib, names = contributions(models, part, features)
        part_reasons = explain.bars_from_contributions(
            contrib, names, part, 3, cwe_names, org_names
        )
        for i, r in zip(np.flatnonzero(mask), part_reasons, strict=True):
            reasons[i] = r
    alpha = float(config.get("alpha", 1.0))
    safety = safety_score(rows)
    ranked = ~rows["cve_id"].isin(kev_ids)
    model_pct = pd.Series(p).where(ranked).pipe(pct)
    safety_pct = safety.where(ranked).pipe(pct)
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
            "signal": warning_signals(con, rows),
            "as_of": rows["snapshot_month"].to_numpy(),
        }
    )


def apply_kev(scored: pd.DataFrame, kev: pd.DataFrame) -> pd.DataFrame:
    """KEV entries: confidence exploited, score 1, as_of the month they were added. Their
    model fields (p_exploit, reasons) stay, so the panel can still explain them."""
    out = scored.set_index("cve_id")
    added = kev.set_index("cve_id")["date_added"]
    ids = out.index.intersection(added.index)
    out.loc[ids, "confidence"] = "exploited"
    out.loc[ids, "basis"] = "kev"
    out.loc[ids, ["score", "score_pct"]] = 1.0
    out.loc[ids, "as_of"] = pd.to_datetime(added.loc[ids]).dt.strftime("%Y-%m").to_numpy()
    return out.reset_index()


def combine(scored: pd.DataFrame, kev: pd.DataFrame) -> pd.DataFrame:
    out = apply_kev(scored.drop_duplicates("cve_id", keep="first"), kev)
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
    kev = kev_dates(con)
    out = combine(score_rows(con, rows, config, set(kev["cve_id"])), kev)
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
        "signals": {str(k): int(v) for k, v in out["signal"].value_counts().items()},
    }
    write_meta(out, config)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "serving_log.json").write_text(json.dumps(log, indent=2) + "\n")
    print(json.dumps(log, indent=2))


if __name__ == "__main__":
    main()
