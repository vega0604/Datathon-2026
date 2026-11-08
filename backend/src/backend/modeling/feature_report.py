"""SHE-117: how well does each feature alone separate future KEV additions, per year?

    uv run python -m backend.modeling.feature_report

For every whitelisted feature (modeling/features.py), on folds 2024 and 2025 only (the
benchmark label; fold 2026 has no labels and is never read):

- numeric and 0/1 features: missing count and KEV rate missing vs present, AUC on present
  rows (auc_dir = max(AUC, 1 - AUC), direction + or -), Spearman rho with the label,
  hits@K and hits@500 ranking by the feature alone in its positive direction (NULLs last,
  ties by cve_id), and the KEV-rate lift in the top 1%;
- categorical features (CVSS 3 metrics, cwe_primary): KEV rate and count per category,
  and an AUC that scores each row with its category's KEV rate from the *other* fold;
- stable = auc_dir >= 0.55 in both folds with the same direction; flips = the direction
  differs; suspect = auc_dir >= 0.90 in either fold (a leak check: expect none);
- redundancy: feature-to-feature Spearman over both folds, pairs with |rho| >= 0.85.

Writes outputs/feature_report.csv, feature_categories.csv, feature_redundancy.csv,
modeling/stable_features.json (committed: SHE-111 reads it) and
outputs/charts/feature_auc.html and .png.
"""

import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from backend.core.config import OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling import features as mf
from backend.modeling.evaluate import evaluate_frame

FOLDS = (2024, 2025)
STABLE_AUC = 0.55
SUSPECT_AUC = 0.90
REDUNDANT_RHO = 0.85
MIN_CWE_ROWS = 200
TOP_SHARE = 0.01
MISSING = "(missing)"
STABLE_PATH = Path(__file__).with_name("stable_features.json")
CHARTS_DIR = OUTPUTS_DIR / "charts"
NUMERIC = [f for f in mf.FEATURES if f not in mf.CATEGORICAL]
COLORS = {2024: "#2a78d6", 2025: "#eb6834"}  # validated categorical slots 1 and 2


# --- measures (pure, unit-tested) ------------------------------------------------------


def auc_direction(values: pd.Series, labels: pd.Series) -> dict:
    """AUC on rows where the value is present, auc_dir and direction. NaN when the present
    rows don't hold both classes."""
    present = values.notna()
    y, x = labels[present].astype(int), values[present].astype(float)
    if y.nunique() < 2:
        return {"auc": math.nan, "auc_dir": math.nan, "direction": None}
    auc = float(roc_auc_score(y, x))
    return {"auc": auc, "auc_dir": max(auc, 1 - auc), "direction": "+" if auc >= 0.5 else "-"}


def spearman(a: pd.Series, b: pd.Series) -> float:
    """Spearman rho on rows where both are present (Pearson on average ranks)."""
    both = a.notna() & b.notna()
    if both.sum() < 3:
        return math.nan
    ra, rb = a[both].rank(), b[both].rank()
    if ra.std() == 0 or rb.std() == 0:
        return math.nan
    return float(np.corrcoef(ra, rb)[0, 1])


def oriented(values: pd.Series, direction: str | None) -> pd.Series:
    """The feature as a score where higher means more likely KEV (NULLs stay NULL)."""
    return -values.astype(float) if direction == "-" else values.astype(float)


def top_lift(
    score: pd.Series, labels: pd.Series, ids: pd.Series, share: float = TOP_SHARE
) -> float:
    """KEV rate in the top `share` by score (NULLs last, ties by cve_id) / base rate."""
    frame = pd.DataFrame(
        {"score": score.to_numpy(), "label": labels.to_numpy(), "id": ids.to_numpy()}
    )
    frame = frame.sort_values(["score", "id"], ascending=[False, True], na_position="last")
    top = frame.head(max(1, math.ceil(len(frame) * share)))
    base = frame["label"].mean()
    return float(top["label"].mean() / base) if base else math.nan


def stability(per_fold: dict[int, dict]) -> dict:
    """stable: auc_dir >= 0.55 in both folds with the same direction; flips: directions
    differ; suspect: auc_dir >= 0.90 in either fold."""
    dirs = [per_fold[f]["direction"] for f in FOLDS]
    aucs = [per_fold[f]["auc_dir"] for f in FOLDS]
    known = all(d is not None for d in dirs)
    flips = known and dirs[0] != dirs[1]
    stable = known and not flips and all(a >= STABLE_AUC for a in aucs)
    suspect = any(a >= SUSPECT_AUC for a in aucs if not math.isnan(a))
    return {
        "mean_auc_dir": float(np.nanmean(aucs))
        if not all(math.isnan(a) for a in aucs)
        else math.nan,
        "stable": bool(stable),
        "flips": bool(flips),
        "suspect": bool(suspect),
        "direction": dirs[0] if not flips else None,
    }


def category_values(series: pd.Series) -> pd.Series:
    return series.astype("string").fillna(MISSING)


def collapse_cwe(values: pd.Series, min_rows: int = MIN_CWE_ROWS) -> pd.Series:
    """cwe_primary categories with fewer than min_rows rows in this fold become "other"."""
    counts = values.value_counts()
    keep = set(counts[counts >= min_rows].index)
    return values.where(values.isin(keep), mf.OTHER)


def category_rates(values: pd.Series, labels: pd.Series) -> pd.DataFrame:
    table = pd.DataFrame({"category": values, "label": labels.astype(int)})
    out = table.groupby("category")["label"].agg(rows="size", kev="sum").reset_index()
    out["kev_rate"] = out["kev"] / out["rows"]
    return out


def cross_fold_scores(
    values: pd.Series, other_values: pd.Series, other_labels: pd.Series
) -> pd.Series:
    """Score each row with its category's KEV rate in the other fold (that fold's base rate
    for a category it never saw), so a fold never scores itself."""
    rates = category_rates(other_values, other_labels).set_index("category")["kev_rate"]
    base = other_labels.astype(int).mean()
    return values.map(rates).astype(float).fillna(base)


def redundant_pairs(frame: pd.DataFrame, threshold: float = REDUNDANT_RHO) -> list[dict]:
    """Feature pairs with |Spearman rho| >= threshold (pairwise complete rows)."""
    rho = frame.rank().corr()
    pairs = []
    columns = list(rho.columns)
    for i, a in enumerate(columns):
        for b in columns[i + 1 :]:
            value = rho.loc[a, b]
            if not math.isnan(value) and abs(value) >= threshold:
                pairs.append({"feature_a": a, "feature_b": b, "rho": round(float(value), 4)})
    return sorted(pairs, key=lambda p: -abs(p["rho"]))


# --- report -------------------------------------------------------------------------------


def hits(con, fold: int, part: pd.DataFrame, score: pd.Series) -> tuple[int, int, int]:
    r = evaluate_frame(con, fold, pd.DataFrame({"cve_id": part["cve_id"], "score": score}))
    return r["k"], r["hits_at_k"], r["hits_at_500"]


def numeric_rows(con, data: pd.DataFrame) -> list[dict]:
    rows = []
    for feature in NUMERIC:
        for fold in FOLDS:
            part = data[data["fold"] == fold]
            values, labels = part[feature], part["label"]
            missing = values.isna()
            ad = auc_direction(values, labels)
            score = oriented(values, ad["direction"] or "+")
            k, hk, h500 = hits(con, fold, part, score)
            rows.append(
                {
                    "feature": feature, "kind": "numeric", "fold": fold,
                    "rows": len(part), "positives": int(labels.sum()),
                    "n_missing": int(missing.sum()),
                    "positives_present": int(labels[~missing].sum()),
                    "kev_rate_missing": float(labels[missing].mean()) if missing.any() else math.nan,
                    "kev_rate_present": float(labels[~missing].mean()) if (~missing).any() else math.nan,
                    **ad, "spearman": spearman(values.astype(float), labels.astype(float)),
                    "k": k, "hits_at_k": hk, "hits_at_500": h500,
                    "top1pct_lift": top_lift(score, labels, part["cve_id"]),
                }
            )  # fmt: skip
    return rows


def categorical_rows(con, data: pd.DataFrame) -> tuple[list[dict], list[dict]]:
    rows, tables = [], []
    for feature in mf.CATEGORICAL:
        values = {f: category_values(data.loc[data["fold"] == f, feature]) for f in FOLDS}
        if feature == "cwe_primary":
            values = {f: collapse_cwe(v) for f, v in values.items()}
        for fold in FOLDS:
            part = data[data["fold"] == fold]
            other = next(f for f in FOLDS if f != fold)
            labels = part["label"]
            for r in category_rates(values[fold], labels).to_dict("records"):
                tables.append({"feature": feature, "fold": fold, **r})
            score = cross_fold_scores(
                values[fold], values[other], data.loc[data["fold"] == other, "label"]
            )
            ad = auc_direction(score, labels)
            k, hk, h500 = hits(con, fold, part, score)
            missing = values[fold] == MISSING
            rows.append(
                {
                    "feature": feature, "kind": "categorical", "fold": fold,
                    "rows": len(part), "positives": int(labels.sum()),
                    "n_missing": int(missing.sum()),
                    "positives_present": int(labels[~missing].sum()),
                    "kev_rate_missing": float(labels[missing].mean()) if missing.any() else math.nan,
                    "kev_rate_present": float(labels[~missing].mean()) if (~missing).any() else math.nan,
                    **ad, "spearman": spearman(score, labels.astype(float)),
                    "k": k, "hits_at_k": hk, "hits_at_500": h500,
                    "top1pct_lift": top_lift(score, labels, part["cve_id"]),
                }
            )  # fmt: skip
    return rows, tables


def summary_rows(rows: list[dict]) -> list[dict]:
    out = []
    for feature in mf.FEATURES:
        per_fold = {r["fold"]: r for r in rows if r["feature"] == feature}
        s = stability(per_fold)
        out.append({"feature": feature, "kind": per_fold[FOLDS[0]]["kind"], "fold": "both", **s})
    return out


def chart(summary: list[dict], rows: list[dict]) -> None:
    import plotly.graph_objects as go

    order = sorted(
        (s for s in summary if not math.isnan(s["mean_auc_dir"])), key=lambda s: s["mean_auc_dir"]
    )
    names = [s["feature"] for s in order]
    by = {(r["feature"], r["fold"]): r["auc_dir"] for r in rows}
    fig = go.Figure()
    for name in names:  # one gray connector per feature, under the dots
        fig.add_trace(
            go.Scatter(
                x=[by[(name, f)] for f in FOLDS], y=[name, name], mode="lines",
                line={"color": "#c3c2b7", "width": 2}, hoverinfo="skip", showlegend=False,
            )
        )  # fmt: skip
    for fold in FOLDS:
        fig.add_trace(
            go.Scatter(
                x=[by[(n, fold)] for n in names], y=names, mode="markers", name=str(fold),
                marker={"color": COLORS[fold], "size": 9, "line": {"color": "#fcfcfb", "width": 2}},
                hovertemplate="%{y}<br>" + str(fold) + " AUC (best direction) %{x:.3f}<extra></extra>",
            )
        )  # fmt: skip
    fig.add_vline(x=0.5, line={"color": "#52514e", "width": 1, "dash": "dot"})
    fig.update_layout(
        title={"text": "How well each feature alone ranks future KEV additions (AUC, best direction)",
               "font": {"color": "#0b0b0b", "size": 16}},
        xaxis={"title": "AUC (0.5 = no better than chance)", "range": [0.45, 1.0],
               "gridcolor": "#ecebe7", "color": "#52514e"},
        yaxis={"color": "#52514e", "tickfont": {"size": 11}},
        legend={"title": {"text": "Fold"}, "orientation": "h", "y": 1.02, "x": 0},
        plot_bgcolor="#fcfcfb", paper_bgcolor="#fcfcfb",
        height=max(420, 22 * len(names) + 140), width=900, margin={"l": 200, "r": 30, "t": 90, "b": 60},
    )  # fmt: skip
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    fig.write_html(CHARTS_DIR / "feature_auc.html", include_plotlyjs="cdn")
    fig.write_image(CHARTS_DIR / "feature_auc.png", scale=2)


def write_csv(rows: list[dict], name: str) -> None:
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(OUTPUTS_DIR / name, index=False, lineterminator="\n")


def main() -> None:
    con = connect()
    data = mf.load(con, folds=FOLDS)  # benchmark label; 2026 never loaded
    rows = numeric_rows(con, data)
    cat_rows, tables = categorical_rows(con, data)
    rows += cat_rows
    summary = summary_rows(rows)
    pooled = data[NUMERIC].astype(float)
    pairs = redundant_pairs(pooled)

    write_csv(rows + summary, "feature_report.csv")
    write_csv(tables, "feature_categories.csv")
    write_csv(
        pairs or [{"feature_a": None, "feature_b": None, "rho": None}], "feature_redundancy.csv"
    )
    stable = sorted((s for s in summary if s["stable"]), key=lambda s: -s["mean_auc_dir"])
    STABLE_PATH.write_text(
        json.dumps(
            {"rule": f"auc_dir >= {STABLE_AUC} in 2024 and 2025 with the same direction",
             "features": [{"feature": s["feature"], "direction": s["direction"],
                           "mean_auc_dir": round(s["mean_auc_dir"], 4)} for s in stable]},
            indent=2,
        ) + "\n"
    )  # fmt: skip
    chart(summary, rows)

    by = {(r["feature"], r["fold"]): r for r in rows}
    print("Top 10 by mean auc_dir (2024 / 2025, hits@K 2024 / 2025):")
    for s in sorted(summary, key=lambda s: -np.nan_to_num(s["mean_auc_dir"]))[:10]:
        a, b = by[(s["feature"], 2024)], by[(s["feature"], 2025)]
        print(f"  {s['feature']:<26} {a['auc_dir']:.3f} / {b['auc_dir']:.3f}   "
              f"{a['hits_at_k']} / {b['hits_at_k']}   {'stable' if s['stable'] else ''}")  # fmt: skip
    print(f"Stable ({len(stable)}): {', '.join(s['feature'] for s in stable)}")
    print(f"Flipping: {', '.join(s['feature'] for s in summary if s['flips']) or 'none'}")
    print(f"Suspect (auc_dir >= {SUSPECT_AUC}): "
          f"{', '.join(s['feature'] for s in summary if s['suspect']) or 'none'}")  # fmt: skip
    for s in summary:
        if s["suspect"]:
            present = [by[(s["feature"], f)]["positives_present"] for f in FOLDS]
            print(
                f"  {s['feature']}: positives with a value {present[0]} (2024) / {present[1]} (2025)"
            )
    print(
        "Redundant pairs:",
        ", ".join(f"{p['feature_a']}~{p['feature_b']} {p['rho']}" for p in pairs) or "none",
    )


if __name__ == "__main__":
    main()
