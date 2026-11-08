"""Benchmark-wide numbers for the Insights pages, written once per model run.

    uv run python -m backend.modeling.insights   # after select / serving

Writes data/features/insights.json, which the API serves as-is:
- summary: catch rate of our top 500 (2025 backtest), benchmark KPIs, KEV rate by CVSS
  band and by weakness type;
- catch_rate: share of 2025's exploited CVEs caught as more are fixed, for our ranking and
  the three README rankings, plus a 2-D map of Granite description embeddings;
- vendors: CVE count and KEV rate for the largest vendors;
- benchmark: the facts behind the "About this data" box.

The catch-rate curves use the 2025 backtest fold (train on 2024, test on 2025), with the
number fixed scaled to the benchmark's size (500 of 72,670 = 243 of 35,281): the 2026
answers are not available.
"""

import json
from collections import Counter
from datetime import UTC, datetime

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from backend.core.config import FEATURES_DIR, INSIGHTS_PATH, OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling import features as mf
from backend.modeling.baselines import BASELINES, baseline_source
from backend.modeling.blend import blend
from backend.modeling.evaluate import BENCHMARK_PICKS, BENCHMARK_ROWS
from backend.modeling.final import final_config
from backend.modeling.safety import safety_score
from backend.modeling.train import SEEDS, fit, rank_average
from backend.modeling.train import score as predict

TEST_FOLD, TRAIN_FOLD = 2025, 2024
BEST_PUBLIC_HITS = 8  # README: "Public exploit code first, then EPSS" finds 8 in the top 500
CURVE_MAX, CURVE_STEP = 5_000, 100
NOT_REVIEWED = ("Deferred", "Awaiting Analysis", "Received", "Undergoing Analysis")
BANDS = (("critical", 9.0, 10.0), ("high", 7.0, 8.9), ("medium", 4.0, 6.9), ("low", 0.1, 3.9))
EMBED_POINTS, EMBED_KEV, CLUSTERS, SEED = 200, 22, 6, 7


# --- curves (pure, unit-tested) ----------------------------------------------------------------


def catch_curve(order: list[int], fold_rows: int, positives: int) -> list[dict]:
    """order: labels (0/1) in ranked order. Points every CURVE_STEP benchmark-equivalent
    CVEs fixed, from 0 to CURVE_MAX."""
    labels = np.asarray(order, dtype=int)
    cum = np.concatenate([[0], np.cumsum(labels)])
    points = []
    for fixed in range(0, CURVE_MAX + 1, CURVE_STEP):
        cut = min(len(labels), round(fixed * fold_rows / BENCHMARK_ROWS))
        points.append({"fixed": fixed, "caught_share": round(float(cum[cut] / positives), 4)})
    return points


def share_at(points: list[dict], fixed: int) -> float:
    return next(p["caught_share"] for p in points if p["fixed"] == fixed)


# --- rankings on the 2025 backtest fold --------------------------------------------------------


def model_order(con, data: pd.DataFrame, config: dict) -> pd.DataFrame:
    """The submitted ranking on 2025: the final model's settings trained on 2024 (5 seeds,
    rank-averaged) and blended with the safety ranker at the submitted alpha."""
    train, test = (
        data[data["fold"] == TRAIN_FOLD],
        data[data["fold"] == TEST_FOLD].reset_index(drop=True),
    )
    features = list(config["features"])
    seeds = []
    for s in SEEDS:
        booster, categories = fit(train, config["params"], s, features)
        seeds.append(predict(booster, test, categories, features).reset_index(drop=True))
    model = rank_average(seeds)["rank_avg"]
    alpha = float(config.get("alpha", 1.0))
    score = blend(model, pd.Series(safety_score(test).to_numpy()), alpha) if alpha < 1 else model
    return test.assign(score=score.to_numpy())


def ordered_labels(df: pd.DataFrame, order_by: list[tuple[str, bool]]) -> list[int]:
    cols = [c for c, _ in order_by] + ["cve_id"]
    asc = [a for _, a in order_by] + [True]
    return df.sort_values(cols, ascending=asc, na_position="last", kind="mergesort")[
        "label"
    ].tolist()


def curves(con, data: pd.DataFrame, config: dict) -> tuple[list[dict], int, int]:
    test = model_order(con, data, config)
    rows, positives = len(test), int(test["label"].sum())
    base = con.execute(
        f"SELECT cve_id, raw_cvss3_score, epss, any_exploit_code FROM {baseline_source()} "
        f"WHERE fold = {TEST_FOLD}"
    ).df()
    test = test.drop(columns=["epss", "any_exploit_code"]).merge(base, on="cve_id")
    rankings = [
        ("model", "Our model", [("score", False)]),
        ("exploit_epss", "Exploit + EPSS", [("any_exploit_code", False), ("epss", False)]),
        ("epss", "EPSS", [("epss", False)]),
        ("cvss", "Highest CVSS", [("raw_cvss3_score", False), ("epss", False)]),
    ]
    assert set(BASELINES) == {"cvss_first", "epss_first", "exploit_then_epss"}
    out = [
        {"ranking": key, "label": label,
         "points": catch_curve(ordered_labels(test, order), rows, positives)}
        for key, label, order in rankings
    ]  # fmt: skip
    return out, rows, positives


# --- embedding map -------------------------------------------------------------------------------


def embedding_map(con, data: pd.DataFrame) -> dict:
    """About 200 description embeddings from the backtest years (22 on KEV), projected to 2-D
    with PCA, scaled to 0-1 with y = 0 at the top; 6 k-means clusters named by their most
    common weakness."""
    from sklearn.cluster import KMeans
    from sklearn.decomposition import PCA

    path = FEATURES_DIR / "embeddings.parquet"
    if not path.exists():
        return {"points": [], "clusters": []}
    table = pq.read_table(path)
    ids = table["cve_id"].to_pylist()
    column = table["embedding"].combine_chunks()
    matrix = column.flatten().to_numpy().reshape(len(column), column.type.list_size)
    index = {c: i for i, c in enumerate(ids)}
    kev = {r[0] for r in con.execute("SELECT cve_id FROM known_exploited").fetchall()}
    pool = data[data["cve_id"].isin(index.keys())].drop_duplicates("cve_id")
    on_kev = pool[pool["cve_id"].isin(kev)]
    rest = pool[~pool["cve_id"].isin(kev)]
    picked = pd.concat(
        [on_kev.sample(min(EMBED_KEV, len(on_kev)), random_state=SEED),
         rest.sample(EMBED_POINTS - min(EMBED_KEV, len(on_kev)), random_state=SEED)]
    )  # fmt: skip
    vectors = matrix[[index[c] for c in picked["cve_id"]]]
    xy = PCA(n_components=2, random_state=SEED).fit_transform(vectors)
    xy = (xy - xy.min(axis=0)) / (xy.max(axis=0) - xy.min(axis=0))
    xy[:, 1] = 1 - xy[:, 1]  # y = 0 at the top
    labels = KMeans(n_clusters=CLUSTERS, n_init=10, random_state=SEED).fit_predict(xy)
    names = dict(con.execute("SELECT cwe_id, name FROM weakness_types").fetchall())
    cwes = picked["cwe_primary"].to_numpy()
    cluster_cwes = cluster_labels([list(cwes[labels == k]) for k in range(CLUSTERS)])
    clusters = []
    for k, cwe in enumerate(cluster_cwes):
        label = short_cwe(names.get(cwe, cwe)) if cwe else "Mixed"
        centre = xy[labels == k].mean(axis=0)
        clusters.append(
            {"label": label, "x": round(float(centre[0]), 4), "y": round(float(centre[1]), 4)}
        )
    return {
        "points": [
            {"cve_id": c, "x": round(float(x), 4), "y": round(float(y), 4), "on_kev": c in kev}
            for c, (x, y) in zip(picked["cve_id"], xy, strict=True)
        ],
        "clusters": clusters,
    }


def cluster_labels(members: list[list[str]]) -> list[str | None]:
    """One weakness per cluster, never the same one twice: the largest cluster picks its
    most common weakness first, each next one its most common weakness not yet taken
    (None when none is left, shown as "Mixed")."""
    taken: set[str] = set()
    out: list[str | None] = [None] * len(members)
    for k in sorted(range(len(members)), key=lambda k: -len(members[k])):
        counts = Counter(m for m in members[k] if m not in ("unknown", "other") and m not in taken)
        if counts:
            out[k] = counts.most_common(1)[0][0]
            taken.add(out[k])
    return out


def short_cwe(name: str) -> str:
    """'Improper Neutralization of Special Elements used in an OS Command ('OS Command
    Injection')' -> 'OS Command Injection'."""
    if "('" in name and name.endswith("')"):
        return name[name.index("('") + 2 : -2]
    return name if len(name) <= 40 else name[:39].rstrip() + "…"


# --- summary and vendors -------------------------------------------------------------------------


def severity_bands(con) -> list[dict]:
    out = []
    for band, low, high in BANDS:
        share = con.execute(
            f"""
            SELECT avg((k.cve_id IS NOT NULL)::INT) FROM vulnerabilities v
            LEFT JOIN known_exploited k USING (cve_id)
            WHERE v.cvss3_score >= {low} AND v.cvss3_score < {high + 0.1}
            """
        ).fetchone()[0]
        out.append({"band": band, "cvss_min": low, "cvss_max": high, "kev_share": round(share, 5)})
    return out


def weaknesses(con, top: int = 15) -> dict:
    rows = con.execute(
        """
        WITH x AS (
            SELECT trim(split_part(coalesce(v.cwe_ids, ''), ';', 1)) AS cwe,
                   (k.cve_id IS NOT NULL)::INT AS kev
            FROM vulnerabilities v LEFT JOIN known_exploited k USING (cve_id)
        )
        SELECT x.cwe, w.name, count(*) AS n, sum(kev) AS kev
        FROM x JOIN weakness_types w ON w.cwe_id = x.cwe
        GROUP BY ALL ORDER BY n DESC
        """
    ).fetchall()
    total, total_kev = sum(r[2] for r in rows), sum(r[3] for r in rows)
    items = [
        {"cwe_id": cwe, "name": short_cwe(name), "cve_count": int(n), "kev_count": int(k),
         "kev_share": round(k / n, 5)}
        for cwe, name, n, k in rows[:top]
    ]  # fmt: skip
    return {"overall_kev_share": round(total_kev / total, 5), "items": items}


def vendors(con, top: int = 10) -> dict:
    rows = con.execute(
        """
        WITH v AS (
            SELECT DISTINCT a.cve_id, a.vendor_key
            FROM clean.affected_products a WHERE a.vulnerable = 'Y' AND a.vendor_key IS NOT NULL
        ),
        names AS (
            -- CISA's display names; KEV vendor keys use the CPE vendor-key rule
            SELECT vendor_key AS key, mode(vendor) AS name FROM clean.kev
            WHERE vendor_key IS NOT NULL GROUP BY 1
        )
        SELECT coalesce(n.name, v.vendor_key) AS vendor, count(DISTINCT v.cve_id) AS cves,
               count(DISTINCT k.cve_id) AS kev
        FROM v LEFT JOIN known_exploited k USING (cve_id)
        LEFT JOIN names n ON n.key = v.vendor_key
        GROUP BY 1 ORDER BY cves DESC
        """
    ).fetchall()
    cells = [
        {"vendor": name if not name.islower() else name.capitalize(), "cve_count": int(n),
         "kev_share": round(k / n, 5)}
        for name, n, k in rows[:top]
    ]  # fmt: skip
    rest_n = sum(r[1] for r in rows[top:])
    rest_k = sum(r[2] for r in rows[top:])
    cells.append(
        {"vendor": "Other", "cve_count": int(rest_n), "kev_share": round(rest_k / rest_n, 5)}
    )
    ranking = [c["vendor"] for c in sorted(cells[:top], key=lambda c: -c["kev_share"])[:4]]
    best = max(cells[:top], key=lambda c: c["kev_share"])
    return {
        "cells": cells,
        "ranking": ranking,
        "takeaway": f"{best['vendor']} has the highest KEV rate of the largest vendors: "
        f"{best['kev_share']:.1%} of its {best['cve_count']:,} CVEs were exploited.",
    }


def build(con) -> dict:
    config = final_config()
    data = mf.load(con, folds=(TRAIN_FOLD, TEST_FOLD))
    curve_list, fold_rows, positives = curves(con, data, config)
    model_points = curve_list[0]["points"]
    caught = share_at(model_points, BENCHMARK_PICKS)
    best_public = share_at(curve_list[1]["points"], BENCHMARK_PICKS)
    year = con.execute(
        f"""
        SELECT count(*), count(*) FILTER (WHERE nvd_status IN {NOT_REVIEWED})
        FROM vulnerabilities WHERE year(published) = 2026
        """
    ).fetchone()
    vulns, kev = con.execute(
        "SELECT (SELECT count(*) FROM vulnerabilities), (SELECT count(*) FROM known_exploited)"
    ).fetchone()
    bands = severity_bands(con)
    crit, med = bands[0]["kev_share"], bands[2]["kev_share"]
    weak = weaknesses(con)
    top_weak = max(weak["items"], key=lambda w: w["kev_share"])
    top500 = OUTPUTS_DIR / "top500.csv"
    top_n_ready = top500.exists() and len(pd.read_csv(top500)) == BENCHMARK_PICKS
    benchmark_cves = con.execute("SELECT count(*) FROM scoreboard_2026").fetchone()[0]
    return {
        "built_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "summary": {
            "coverage": {
                "top_n": BENCHMARK_PICKS,
                "caught_share": caught,
                "backtest_year": TEST_FOLD,
                "positives": positives,
            },
            "kpis": {
                "benchmark_cves": benchmark_cves,
                "nist_unreviewed": int(year[1]),
                "nist_unreviewed_share_this_year": round(year[1] / year[0], 4),
            },
            "versus_public": {
                "best_public_hits_in_top_n": BEST_PUBLIC_HITS,
                "best_public_caught_share": best_public,
                "any_cve_exploited_rate": round(kev / vulns, 5),
            },
            "severity_bands": bands,
            "weaknesses": weak,
            "takeaways": {
                "severity": f"Critical CVEs reach KEV about {crit / med:.0f}× as often as Medium "
                f"ones, yet only {crit:.1%} of Critical CVEs ever do.",
                "weaknesses": f"{top_weak['name']} has the highest KEV rate of the common "
                f"weakness types: {top_weak['kev_share']:.1%} of its CVEs.",
                "coverage": f"In the 2025 backtest, our top {BENCHMARK_PICKS} (scaled) caught "
                f"{caught:.0%} of exploited CVEs; exploit code + EPSS caught {best_public:.0%}.",
            },
        },
        "catch_rate": {
            "curves": curve_list,
            "top_n": {
                "fixed": BENCHMARK_PICKS,
                "share_of_queue": round(BENCHMARK_PICKS / BENCHMARK_ROWS, 4),
                "caught_share": caught,
            },
            "backtest": {
                "train_year": TRAIN_FOLD,
                "test_year": TEST_FOLD,
                "fold_rows": fold_rows,
                "positives": positives,
            },
            "embedding": embedding_map(con, data),
            "takeaways": {
                "curves": f"Fixing the top {BENCHMARK_PICKS} by our ranking catches {caught:.0%} "
                f"of the CVEs exploited later, against {best_public:.0%} for exploit code + EPSS.",
                "embedding": "Descriptions of exploited CVEs (diamonds) sit close together: "
                "Granite's embedding places similar attacks near each other.",
            },
        },
        "vendors": vendors(con),
        "benchmark": {
            "train_years": [TRAIN_FOLD],
            "test_years": [TEST_FOLD],
            "final_train_years": [TRAIN_FOLD, TEST_FOLD],
            "cves_scored": benchmark_cves,
            "top_n": BENCHMARK_PICKS,
            "top_n_file": "top500.csv",
            "top_n_ready": bool(top_n_ready),
            "data_checked": datetime.now(UTC).date().isoformat(),
        },
    }


def write(con) -> dict:
    """Build the insights and write insights.json (atomically: the API may be reading)."""
    out = build(con)
    INSIGHTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = INSIGHTS_PATH.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(out, indent=2, default=str, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    tmp.replace(INSIGHTS_PATH)
    return out


def main() -> None:
    out = write(connect())
    s = out["summary"]
    print(f"wrote {INSIGHTS_PATH}")
    print(f"coverage {s['coverage']}")
    print(f"kpis {s['kpis']}")
    for c in out["catch_rate"]["curves"]:
        print(f"{c['label']:<16} at 500: {share_at(c['points'], 500):.2%}  at 5000: "
              f"{c['points'][-1]['caught_share']:.2%}")  # fmt: skip
    print(f"vendors {out['vendors']['ranking']}")


if __name__ == "__main__":
    main()
