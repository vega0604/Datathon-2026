"""Unit tests for the SHE-46 point-in-time KEV similarity, with tiny hand-made vectors."""

import duckdb
import numpy as np
import pandas as pd
import pytest

from backend.pipeline.features import add_similarity_sql
from backend.pipeline.similarity import kev_similarity


def unit(*values):
    v = np.array(values, dtype=np.float32)
    return v / np.linalg.norm(v)


VECTORS = {
    "CVE-A": unit(1, 0, 0),  # the vulnerability being scored
    "K-OLD": unit(1, 1, 0),  # on KEV before the snapshot: cosine 0.7071 with A
    "K-NEW": unit(1, 0, 0),  # on KEV after the snapshot: identical to A, must be ignored
    "K-FAR": unit(0, 0, 1),  # on KEV before the snapshot: cosine 0 with A
}
KEV = pd.DataFrame(
    {
        "cve_id": ["K-OLD", "K-NEW", "K-FAR"],
        "date_added": pd.to_datetime(["2024-01-10", "2024-03-05", "2024-01-20"]),
    }
)


def population(*rows):
    return pd.DataFrame(rows, columns=["cve_id", "fold", "snapshot_end"]).assign(
        snapshot_end=lambda d: pd.to_datetime(d["snapshot_end"])
    )


def test_kev_added_after_the_snapshot_is_ignored():
    out = kev_similarity(population(("CVE-A", 2024, "2024-02-29")), VECTORS, KEV)
    assert out["kev_sim_max"].iloc[0] == pytest.approx(0.70711, abs=1e-4)
    later = kev_similarity(population(("CVE-A", 2024, "2024-03-31")), VECTORS, KEV)
    assert later["kev_sim_max"].iloc[0] == pytest.approx(1.0)


def test_added_on_the_snapshot_day_counts():
    out = kev_similarity(population(("CVE-A", 2024, "2024-03-05")), VECTORS, KEV)
    assert out["kev_sim_max"].iloc[0] == pytest.approx(1.0)


def test_own_cve_is_excluded():
    # K-OLD scored against KEV at the end of March: itself must not count.
    out = kev_similarity(population(("K-OLD", 2024, "2024-03-31")), VECTORS, KEV)
    assert out["kev_sim_max"].iloc[0] == pytest.approx(0.70711, abs=1e-4)  # vs K-NEW


def test_top5_mean_uses_all_references_when_fewer_than_5():
    out = kev_similarity(population(("CVE-A", 2024, "2024-02-29")), VECTORS, KEV)
    assert out["kev_sim_top5"].iloc[0] == pytest.approx((0.70711 + 0.0) / 2, abs=1e-4)


def test_top5_mean_takes_the_5_highest():
    vectors = {"X": unit(1, 0)} | {f"K{i}": unit(1, i) for i in range(7)}
    kev = pd.DataFrame(
        {"cve_id": [f"K{i}" for i in range(7)], "date_added": pd.to_datetime(["2024-01-01"] * 7)}
    )
    out = kev_similarity(population(("X", 2024, "2024-01-31")), vectors, kev)
    sims = sorted((float(vectors["X"] @ vectors[f"K{i}"]) for i in range(7)), reverse=True)
    assert out["kev_sim_top5"].iloc[0] == pytest.approx(np.mean(sims[:5]), abs=1e-6)
    assert out["kev_sim_max"].iloc[0] == pytest.approx(1.0)


def test_scores_stay_within_cosine_range():
    v = unit(0.3, 0.7, 0.1, 0.9)
    vectors = {"X": v, "K": v * np.float32(1.000001)}  # rounding pushes the dot product > 1
    kev = pd.DataFrame({"cve_id": ["K"], "date_added": pd.to_datetime(["2024-01-01"])})
    out = kev_similarity(population(("X", 2024, "2024-01-31")), vectors, kev)
    assert out["kev_sim_max"].iloc[0] == 1.0
    assert out["kev_sim_top5"].iloc[0] == 1.0


def test_no_embedding_gives_null():
    out = kev_similarity(population(("CVE-MISSING", 2024, "2024-02-29")), VECTORS, KEV)
    assert out["kev_sim_max"].isna().all()
    assert out["kev_sim_top5"].isna().all()


def test_no_reference_yet_gives_null():
    out = kev_similarity(population(("CVE-A", 2024, "2023-12-31")), VECTORS, KEV)
    assert out["kev_sim_max"].isna().all()


def test_feature_step_keeps_every_row():
    con = duckdb.connect()
    con.execute(
        "CREATE TABLE f AS SELECT * "
        "FROM (VALUES ('A', 2024), ('A', 2025), ('B', 2024)) AS t(cve_id, fold)"
    )
    con.execute(
        "CREATE TABLE s AS SELECT * FROM (VALUES ('A', 2024, 0.9::DOUBLE, 0.8::DOUBLE)) "
        "AS t(cve_id, fold, kev_sim_max, kev_sim_top5)"
    )
    rows = con.execute(
        f"SELECT cve_id, fold, kev_sim_max FROM ({add_similarity_sql('f', 's')}) ORDER BY ALL"
    ).fetchall()
    assert rows == [("A", 2024, 0.9), ("A", 2025, None), ("B", 2024, None)]


def test_one_row_per_population_row_in_order():
    pop = population(
        ("CVE-A", 2025, "2024-03-31"),
        ("CVE-MISSING", 2024, "2024-02-29"),
        ("CVE-A", 2024, "2024-02-29"),
    )
    out = kev_similarity(pop, VECTORS, KEV)
    assert list(zip(out["cve_id"], out["fold"], strict=True)) == [
        ("CVE-A", 2025),
        ("CVE-MISSING", 2024),
        ("CVE-A", 2024),
    ]
    assert out["kev_sim_max"].round(4).tolist()[0] == 1.0
