import pytest

from backend.services.versions import compare, in_range


def test_compare_pep440():
    assert compare("1.0", "1.0.0") == 0
    assert compare("2.10", "2.9") == 1
    assert compare("1.0", "1.1") == -1


def test_compare_loose_letters():
    assert compare("1.1.1w", "1.1.1") == 1
    assert compare("1.1.1", "1.1.1w") == -1
    assert compare("1.1.1a", "1.1.1b") == -1
    assert compare("13.1-49.13", "13.1-49.13") == 0
    assert compare("13.1-50.1", "13.1-49.13") == 1


@pytest.mark.parametrize(
    ("version", "bounds", "expected"),
    [
        ("1.5", {"start_inc": "1.0", "end_exc": "2.0"}, True),
        ("1.0", {"start_inc": "1.0"}, True),
        ("0.9", {"start_inc": "1.0"}, False),
        ("1.0", {"start_exc": "1.0"}, False),
        ("1.1", {"start_exc": "1.0"}, True),
        ("2.0", {"end_inc": "2.0"}, True),
        ("2.1", {"end_inc": "2.0"}, False),
        ("2.0", {"end_exc": "2.0"}, False),
        ("1.9", {"end_exc": "2.0"}, True),
        ("1.5", {"exact": "1.5"}, True),
        ("1.5", {"exact": "1.6"}, False),
        ("1.0", {"exact": "1.0.0"}, True),
        ("1.5", {"exact": "*"}, True),
        ("1.5", {"exact": "-"}, True),
        ("1.5", {"exact": ""}, True),
        (None, {"exact": "1.5"}, None),
        (None, {"end_exc": "2.0"}, None),
        ("", {"end_exc": "2.0"}, None),
        (None, {}, True),
        ("1.5", {}, True),
    ],
)
def test_in_range(version, bounds, expected):
    args = {"exact": None, "start_inc": None, "start_exc": None, "end_inc": None, "end_exc": None}
    args.update(bounds)
    assert in_range(version, **args) is expected


def test_loose_letter_version_in_range():
    assert in_range("1.1.1w", None, None, None, "1.1.1w", None) is True
    assert in_range("1.1.1w", None, None, None, None, "1.1.1w") is False
    assert in_range("1.1.1w", None, "1.1.1", None, None, None) is True
