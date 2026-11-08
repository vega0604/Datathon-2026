"""insights.json, built from the real data for the Insights pages."""

import json

import pytest

from backend.core.config import INSIGHTS_PATH

pytestmark = pytest.mark.skipif(
    not INSIGHTS_PATH.exists(),
    reason="no insights: run `uv run python -m backend.modeling.insights`",
)


@pytest.fixture(scope="module")
def data():
    return json.loads(INSIGHTS_PATH.read_text(encoding="utf-8"))


def test_summary_matches_the_readme(data):
    kpis = data["summary"]["kpis"]
    assert kpis["benchmark_cves"] == 72_670
    assert kpis["nist_unreviewed"] == 51_046  # README: NIST hasn't reviewed 51,046 of 92,205
    assert [b["band"] for b in data["summary"]["severity_bands"]] == [
        "critical", "high", "medium", "low",
    ]  # fmt: skip
    assert 0 < data["summary"]["coverage"]["caught_share"] <= 1


def test_curves(data):
    curves = data["catch_rate"]["curves"]
    assert [c["ranking"] for c in curves] == ["model", "exploit_epss", "epss", "cvss"]
    for c in curves:
        assert len(c["points"]) == 51 and c["points"][0] == {"fixed": 0, "caught_share": 0.0}
        shares = [p["caught_share"] for p in c["points"]]
        assert shares == sorted(shares)  # never decreases
    assert len(data["catch_rate"]["embedding"]["points"]) == 200


def test_vendors(data):
    cells = data["vendors"]["cells"]
    assert cells[-1]["vendor"] == "Other" and len(cells) == 11
    assert len(data["vendors"]["ranking"]) == 4
