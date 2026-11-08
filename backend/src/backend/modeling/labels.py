"""SHE-112: training labels with a longer KEV window.

The final model may learn from every KEV addition up to Dec 31, 2025: the KEV file ends
there, before every 2026 snapshot, so nothing it learns comes from a 2026 snapshot's
future. The backtest mirrors that: training labels stop before the test year's first
snapshot. These labels are for training only. population.parquet's `label` stays the
evaluation label and is never changed.
"""

import pandas as pd

# Run -> last KEV date_added a training label may use. One map, so the backtest and the
# final run can't drift apart.
LABEL_ENDS = {
    "primary": "2024-12-31",  # train 2024 -> test 2025 (first 2025 snapshot is Jan 2025)
    "time_reversed": "2025-12-31",  # train 2025 -> test 2024: uses the future by design
    "final": "2025-12-31",  # train 2024 + 2025 -> score 2026
}
LABEL_MODES = ("benchmark", "long")


def train_labels(
    con, rows: pd.DataFrame, label_end: str, kev: str = "known_exploited"
) -> pd.Series:
    """1 when the vulnerability was added to KEV after its snapshot_end and on or before
    label_end, else 0; aligned to rows (which need cve_id and snapshot_end). Rows already
    on KEV by snapshot_end were removed from the population (SHE-25)."""
    cursor = con.cursor()
    try:
        frame = rows[["cve_id", "snapshot_end"]].reset_index(drop=True)
        cursor.register("_label_rows", frame.assign(_i=range(len(frame))))
        labels = cursor.execute(
            f"""
            SELECT r._i, CAST(EXISTS (
                SELECT 1 FROM {kev} AS k
                WHERE k.cve_id = r.cve_id
                  AND k.date_added > CAST(r.snapshot_end AS DATE)
                  AND k.date_added <= DATE '{label_end}'
            ) AS INTEGER) AS label
            FROM _label_rows AS r
            ORDER BY r._i
            """
        ).df()["label"]
    finally:
        cursor.close()
    return pd.Series(labels.to_numpy(), index=rows.index, name="label")
