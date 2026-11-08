"""Unit tests for the SHE-49 top500 writer, on a tiny in-memory scoreboard."""

import duckdb
import pandas as pd
import pytest

from backend.modeling.submission import SubmissionError, pick_top, write_submission

IDS = [f"CVE-2026-{i:05d}" for i in range(600)]


@pytest.fixture
def con():
    con = duckdb.connect()
    con.execute("CREATE TABLE sb AS SELECT unnest(?) AS cve_id", [IDS])
    con.execute(
        """
        CREATE TABLE feats AS
        SELECT cve_id, 2026 AS fold, '2026-07' AS snapshot_month,
               (row_number() OVER () % 2)::UTINYINT AS any_exploit_code, 0.5 AS epss_pct
        FROM sb
        """
    )
    return con


def scores(n=600, ids=IDS):
    return pd.DataFrame({"cve_id": ids[:n], "score": [float(i) for i in range(n)]})


def write(con, frame, tmp_path, model_features=("epss_pct",)):
    return write_submission(
        con,
        frame,
        model_features=list(model_features),
        out_dir=tmp_path,
        scoreboard="sb",
        features_source="feats",
    )


def test_refuses_scores_from_an_audit_model(con, tmp_path):
    for leaky in (["epss_pct", "nvd_status"], ["epss_pct", "cvss3_source_is_nvd"], ["ref_count"]):
        with pytest.raises(SubmissionError, match="audit columns"):
            write(con, scores(), tmp_path, model_features=leaky)
    assert not (tmp_path / "top500.csv").exists()


def test_writes_one_column_of_500(con, tmp_path):
    summary = write(con, scores(), tmp_path)
    out = pd.read_csv(tmp_path / "top500.csv")
    assert list(out.columns) == ["cve_id"]
    assert len(out) == 500
    assert out["cve_id"].iloc[0] == "CVE-2026-00599"  # highest score first
    assert (tmp_path / "top500.csv").read_text().splitlines()[0] == "cve_id"
    scored = pd.read_csv(tmp_path / "top500_scored.csv")
    assert list(scored.columns) == [
        "rank", "cve_id", "score", "snapshot_month", "any_exploit_code", "epss_pct",
    ]  # fmt: skip
    assert summary["rows"] == 500
    assert summary["snapshot_months"] == {"2026-07": 500}
    assert summary["min_epss_pct"] == 0.5


def test_too_few_rows(con, tmp_path):
    with pytest.raises(SubmissionError, match="need exactly 500"):
        write(con, scores(n=499), tmp_path)


def test_duplicate_ids(con, tmp_path):
    frame = scores()
    frame.loc[1, "cve_id"] = frame.loc[0, "cve_id"]
    with pytest.raises(SubmissionError, match="duplicate"):
        write(con, frame, tmp_path)


def test_ids_outside_the_scoreboard(con, tmp_path):
    frame = scores()
    frame.loc[599, "cve_id"] = "CVE-1999-0001"
    with pytest.raises(SubmissionError, match="not in scoreboard_2026"):
        write(con, frame, tmp_path)


def test_null_scores_in_the_top_500(con, tmp_path):
    frame = scores()
    frame.loc[100:, "score"] = None  # only 100 real scores
    with pytest.raises(SubmissionError, match="NULL scores"):
        write(con, frame, tmp_path)
    assert not (tmp_path / "top500.csv").exists()


def test_ties_go_to_the_lower_cve_id():
    frame = pd.DataFrame({"cve_id": ["CVE-B", "CVE-A", "CVE-C"], "score": [1.0, 1.0, 2.0]})
    assert pick_top(frame, n=3)["cve_id"].tolist() == ["CVE-C", "CVE-A", "CVE-B"]
