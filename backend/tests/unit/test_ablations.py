"""Unit tests for the SHE-53 feature-group bookkeeping."""

from collections import Counter

from backend.modeling import ablations
from backend.modeling import features as mf


def test_every_column_is_in_exactly_one_group():
    counts = Counter(c for group in mf.FEATURE_GROUPS.values() for c in group)
    assert all(n == 1 for n in counts.values())
    assert set(counts) == set(mf.FEATURES)


def test_removing_a_group_removes_exactly_its_columns():
    for group, columns in mf.FEATURE_GROUPS.items():
        kept = ablations.without(group)
        assert set(mf.FEATURES) - set(kept) == set(columns)
        assert len(kept) == len(mf.FEATURES) - len(columns)


def test_variants():
    v = ablations.variants()
    assert next(iter(v)) == "all"
    assert set(v) == {"all", "only_signals"} | {f"without_{g}" for g in mf.FEATURE_GROUPS}
    assert v["only_signals"] == mf.FEATURE_GROUPS["signals"]
