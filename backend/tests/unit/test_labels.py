"""Unit tests for the SHE-112 training-only labels."""

import duckdb
import pandas as pd
import pytest

from backend.modeling import comparison
from backend.modeling.labels import LABEL_ENDS, train_labels
from backend.modeling.train import backtest, long_features


@pytest.fixture
def con():
    con = duckdb.connect()
    con.execute(
        """
        CREATE TABLE known_exploited AS SELECT * FROM (VALUES
            ('CVE-ON-SNAPSHOT', DATE '2024-03-31'),
            ('CVE-ON-END', DATE '2024-12-31'),
            ('CVE-DAY-AFTER', DATE '2025-01-01'),
            ('CVE-INSIDE', DATE '2024-06-15')
        ) AS t(cve_id, date_added)
        """
    )
    return con


def rows():
    ids = ["CVE-ON-SNAPSHOT", "CVE-ON-END", "CVE-DAY-AFTER", "CVE-INSIDE", "CVE-NEVER"]
    return pd.DataFrame(
        {"cve_id": ids, "snapshot_end": pd.to_datetime(["2024-03-31"] * 5), "label": 0},
        index=[10, 11, 12, 13, 14],
    )


def test_boundary_days(con):
    labels = train_labels(con, rows(), "2024-12-31")
    assert labels.index.tolist() == [10, 11, 12, 13, 14]  # aligned to the rows
    assert labels.tolist() == [0, 1, 0, 1, 0]


def test_label_ends():
    assert LABEL_ENDS == {
        "primary": "2024-12-31", "time_reversed": "2025-12-31", "final": "2025-12-31",
    }  # fmt: skip


def test_long_mode_drops_days_to_cutoff():
    assert "days_to_cutoff" not in long_features(["epss_pct", "days_to_cutoff"])
    assert long_features(["epss_pct"]) == ["epss_pct"]


def test_long_mode_needs_a_cutoff_and_keeps_the_evaluation_label(con):
    data = rows().assign(fold=2024)
    before = data["label"].copy()
    with pytest.raises(ValueError, match="label_end"):
        backtest(con, data, {}, (2024,), 2025, label_mode="long")
    with pytest.raises(ValueError, match="label_mode"):
        backtest(con, data, {}, (2024,), 2025, label_mode="other")
    train_labels(con, data, "2024-12-31")
    assert data["label"].equals(before)  # the caller's (evaluation) label is untouched


def test_comparison_rows_and_primary_score():
    one = {"k": 243, "hits_at_k": {"mean": 10.0, "min": 9, "max": 12},
           "hits_at_500": {"mean": 18.0, "min": 18, "max": 18}}  # fmt: skip
    other = {**one, "k": 198, "hits_at_k": {"mean": 7.5, "min": 7, "max": 8}}
    out = comparison.rows_for("v", "long", {"primary": one, "time_reversed": other})
    assert [r["direction"] for r in out] == ["primary", "time_reversed"]
    assert {r["primary_score"] for r in out} == {17.5}
    assert set(out[0]) == set(comparison.COLUMNS)


def test_upsert_replaces_in_place(tmp_path):
    path = tmp_path / "c.csv"
    base = {c: 0 for c in comparison.COLUMNS}
    a = {**base, "variant": "a", "labels": "x", "direction": "primary"}
    b = {**base, "variant": "b", "labels": "x", "direction": "primary"}
    comparison.upsert([a, b], path)
    comparison.upsert([{**a, "k": 5}], path)
    out = comparison.read(path)
    assert [(r["variant"], r["k"]) for r in out] == [("a", "5"), ("b", "0")]
