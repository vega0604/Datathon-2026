"""Unit tests for the SHE-40 sample and report. No network."""

from backend.pipeline.granite_quality import confusion, sample_pairs

ROWS = [(f"CVE-2025-{i:04d}", f"vendor{i % 7}", f"product{i}", f"1.{i}") for i in range(60)]


def test_sample_is_fixed_and_balanced():
    pairs = sample_pairs(ROWS, seed=1, n=5)
    assert pairs == sample_pairs(ROWS, seed=1, n=5)
    assert [p["truth"] for p in pairs] == [True] * 5 + [False] * 5
    assert len({p["cve_id"] for p in pairs}) == 10


def test_true_pairs_use_own_products_false_pairs_another_vendor():
    own = {row[0]: row for row in ROWS}
    for pair in sample_pairs(ROWS, seed=2, n=5):
        if pair["truth"]:
            assert own[pair["cve_id"]][1:] == (pair["vendor"], pair["product"], pair["version"])
        else:
            assert pair["product_from"] != pair["cve_id"]
            assert pair["vendor"] != own[pair["cve_id"]][1]


def test_confusion():
    results = [
        {"truth": True, "affected": "yes"},
        {"truth": True, "affected": "unknown"},
        {"truth": False, "affected": "no"},
        {"truth": False, "affected": "yes"},
    ]
    assert confusion(results) == {
        "true_pairs": {"yes": 1, "no": 0, "unknown": 1},
        "false_pairs": {"yes": 1, "no": 1, "unknown": 0},
    }
