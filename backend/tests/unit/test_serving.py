"""Unit tests for the serving table: which rows, at which month, and how groups combine."""

import duckdb
import numpy as np
import pandas as pd

from backend.modeling import serving


def test_kev_rows_score_one_and_keep_their_reasons():
    bar = [{"kind": "exploit", "label": "Public exploit code (Nuclei)", "value": 0.3}]
    scored = pd.DataFrame(
        {"cve_id": ["B", "A"], "confidence": "model", "basis": "latest_signals",
         "score": [0.4, np.nan], "score_pct": [0.5, np.nan], "p_exploit": [0.01, 0.2],
         "reasons": [[], bar], "signal": [None, "exploit_code"], "as_of": "2025-12"}
    )  # fmt: skip
    kev = pd.DataFrame({"cve_id": ["A"], "date_added": pd.to_datetime(["2025-01-15"])})
    out = serving.combine(scored, kev).set_index("cve_id")
    assert out.loc["A", "confidence"] == "exploited"
    assert (out.loc["A", "score"], out.loc["A", "score_pct"]) == (1.0, 1.0)
    assert out.loc["A", "as_of"] == "2025-01"
    assert out.loc["A", "reasons"] == bar  # still explained by the model
    assert out.loc["B", "confidence"] == "model"
    assert list(out.reset_index().columns) == serving.COLUMNS


def test_percentiles_share_the_top_rank_on_ties():
    assert serving.pct(pd.Series([0.1, 0.5, 0.5, 0.9])).tolist() == [0.25, 0.75, 0.75, 1.0]


def test_serve_rows_months_and_cutoffs():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA clean")
    con.execute(
        "CREATE TABLE vulnerabilities AS SELECT * FROM (VALUES "
        "('OLD', DATE '2019-05-01'), ('SIG', DATE '2024-02-10'), ('NEW', DATE '2026-10-03'), "
        "('KEV', DATE '2023-01-01'), ('BOARD', DATE '2026-03-01')) AS t(cve_id, published)"
    )
    con.execute("CREATE TABLE scoreboard_2026 AS SELECT 'BOARD' AS cve_id")
    con.execute("CREATE TABLE clean.kev AS SELECT 'KEV' AS cve_id")
    con.execute(
        "CREATE TABLE sig AS SELECT * FROM (VALUES ('SIG', '2024-03'), ('SIG', '2025-07')) "
        "AS t(cve_id, month)"
    )
    rows = con.execute(
        f"SELECT cve_id, snapshot_month, CAST(cutoff AS VARCHAR), has_signals, fold "
        f"FROM ({serving.serve_rows_sql('sig')}) ORDER BY cve_id"
    ).fetchall()
    assert rows == [
        ("KEV", "2025-12", "2026-11-04", False, serving.SERVE_FOLD),  # scored for its reasons
        ("NEW", "2026-10", "2026-11-04", False, serving.SERVE_FOLD),  # publish month
        ("OLD", "2025-12", "2026-11-04", False, serving.SERVE_FOLD),  # no signals: Dec 2025
        ("SIG", "2025-07", "2025-11-04", True, serving.SERVE_FOLD),  # latest signal month
    ]  # scoreboard rows are scored at their snapshot, from features.parquet


def test_mean_probability_averages_seeds():
    class Booster:
        def __init__(self, value):
            self.value = value

        def predict(self, X):
            return np.full(len(X), self.value)

    df = pd.DataFrame({"epss_pct": [0.1, 0.2]})
    models = [(0, Booster(0.2), {}), (1, Booster(0.4), {})]
    assert serving.mean_probability(models, df, ["epss_pct"]).tolist() == [
        0.30000000000000004, 0.30000000000000004,
    ]  # fmt: skip
