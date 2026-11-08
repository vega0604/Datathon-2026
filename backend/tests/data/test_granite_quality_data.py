"""SHE-40: the match check answers in valid JSON on the fixed 40-pair sample. Skipped until
`uv run python -m backend.pipeline.granite_quality` has been run (it uses watsonx tokens)."""

import json

import pytest

from backend.core.config import LOGS_DIR

LOG_PATH = LOGS_DIR / "granite_quality.json"

pytestmark = pytest.mark.skipif(
    not LOG_PATH.exists(),
    reason="no quality log: run `uv run python -m backend.pipeline.granite_quality` first",
)


def test_valid_json_rate():
    report = json.loads(LOG_PATH.read_text())
    assert report["pairs"] == 40
    assert report["valid_json_rate"] >= 0.95
