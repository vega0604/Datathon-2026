"""Unit tests for the SHE-37 benchmark arithmetic. No model or network needed."""

import numpy as np
import pytest

from backend.pipeline.granite_benchmark import (
    fastest_passing,
    mean_cosine,
    project_minutes,
    project_tokens,
    set_env_values,
)


def test_project_minutes():
    assert project_minutes(100.0, 138_000) == pytest.approx(23.0)
    with pytest.raises(ValueError):
        project_minutes(0, 10)


def test_project_tokens():
    result = project_tokens([(400, 50), (500, 70), (600, 60)], calls=300)
    assert result["mean_prompt_tokens"] == 500
    assert result["mean_completion_tokens"] == 60
    assert result["mean_tokens_per_call"] == 560
    assert result["projected_tokens"] == 168_000
    with pytest.raises(ValueError):
        project_tokens([])


def test_mean_cosine():
    a = np.array([[1.0, 0.0], [0.0, 2.0]])
    assert mean_cosine(a, a * 3) == pytest.approx(1.0)
    assert mean_cosine(a, np.array([[0.0, 1.0], [0.0, 1.0]])) == pytest.approx(0.5)


def test_fastest_passing_ignores_failures():
    runs = [
        {"name": "torch-256", "desc_per_second": 20.0, "passed": True},
        {"name": "onnx-256", "desc_per_second": 50.0, "passed": False},  # vectors differ
        {"name": "openvino-gpu-256", "passed": False, "error": "no GPU"},
        {"name": "openvino-256", "desc_per_second": 40.0, "passed": True},
    ]
    assert fastest_passing(runs)["name"] == "openvino-256"
    assert fastest_passing([runs[1], runs[2]]) is None


def test_set_env_values_replaces_and_appends():
    text = "WATSONX_APIKEY=secret\nEMBEDDING_BACKEND=torch\n"
    updated = set_env_values(text, {"EMBEDDING_BACKEND": "onnx", "EMBEDDING_BATCH_SIZE": "32"})
    assert updated == "WATSONX_APIKEY=secret\nEMBEDDING_BACKEND=onnx\nEMBEDDING_BATCH_SIZE=32\n"
    assert set_env_values("", {"A": "1"}) == "A=1\n"
