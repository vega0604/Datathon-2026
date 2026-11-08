"""SHE-53: which feature groups matter? The write-up's "what matters" table.

    uv run python -m backend.modeling.ablations

With the chosen parameters (params.json) and 5 seeds, runs the primary backtest (train
2024, test 2025) with all features, without each group in turn, and with only the
signals as a floor. The drop when "similarity" is removed is Granite's measured
contribution. Writes outputs/ablations.csv.
"""

import csv

from backend.core.config import OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling import features as mf
from backend.modeling.train import PROTOCOLS, backtest, load_params


def without(group: str) -> list[str]:
    """Every whitelisted feature except the group's, in whitelist order."""
    removed = set(mf.FEATURE_GROUPS[group])
    return [c for c in mf.FEATURES if c not in removed]


def variants() -> dict[str, list[str]]:
    out = {"all": list(mf.FEATURES)}
    out |= {f"without_{group}": without(group) for group in mf.FEATURE_GROUPS}
    out["only_signals"] = list(mf.FEATURE_GROUPS["signals"])
    return out


def main() -> None:
    con = connect()
    data = mf.load(con, folds=(2024, 2025))
    params = load_params()
    p = PROTOCOLS["primary"]
    rows = []
    for name, columns in variants().items():
        r = backtest(con, data, params, p["train"], p["test"], features=columns)
        rows.append(
            {
                "variant": name,
                "features": len(columns),
                "hits_at_k_mean": r["hits_at_k"]["mean"],
                "hits_at_k_min": r["hits_at_k"]["min"],
                "hits_at_k_max": r["hits_at_k"]["max"],
                "hits_at_500_mean": r["hits_at_500"]["mean"],
                "hits_at_500_min": r["hits_at_500"]["min"],
                "hits_at_500_max": r["hits_at_500"]["max"],
                "ensemble_hits_at_k": r["ensemble"]["hits_at_k"],
                "ensemble_hits_at_500": r["ensemble"]["hits_at_500"],
            }
        )
        print(f"{name:<28} hits@243 {r['hits_at_k']['mean']:.1f}", flush=True)
    base = rows[0]
    for row in rows:
        row["delta_hits_at_k"] = round(row["hits_at_k_mean"] - base["hits_at_k_mean"], 2)
        row["delta_hits_at_500"] = round(row["hits_at_500_mean"] - base["hits_at_500_mean"], 2)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUTS_DIR / "ablations.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(
        f"\n{'variant':<28} {'@243 mean [min-max]':<22} {'delta':>6}  {'@500 mean':>9} {'delta':>6}"
    )
    for row in sorted(rows, key=lambda r: r["delta_hits_at_k"]):
        print(
            f"{row['variant']:<28} {row['hits_at_k_mean']:>5.1f} "
            f"[{row['hits_at_k_min']}-{row['hits_at_k_max']}]{'':<12} {row['delta_hits_at_k']:>6.1f}"
            f"  {row['hits_at_500_mean']:>9.1f} {row['delta_hits_at_500']:>6.1f}"
        )


if __name__ == "__main__":
    main()
