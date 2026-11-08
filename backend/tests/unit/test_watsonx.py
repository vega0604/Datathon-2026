"""Unit tests for the watsonx client and match-check prompt (SHE-38). A fake model stands in
for watsonx: these tests never touch the network."""

import json
import time

import pytest

from backend.core import config
from backend.services import watsonx
from backend.services.match_check import (
    MAX_DESCRIPTION_CHARS,
    SCHEMA,
    build_match_prompt,
    truncate,
)


class FakeModel:
    """Answers every chat with the next reply in `replies`, recording what it was sent."""

    def __init__(self, replies=('{"affected": "no"}',), prompt_tokens=100, completion_tokens=20):
        self.replies = list(replies)
        self.usage = {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens}
        self.calls = []

    def chat(self, messages, params):
        self.calls.append({"messages": messages, "params": params})
        reply = self.replies[min(len(self.calls), len(self.replies)) - 1]
        return {"choices": [{"message": {"content": reply}}], "usage": self.usage}


@pytest.fixture(autouse=True)
def fresh_counter():
    watsonx.reset_tokens_used()
    yield
    watsonx.reset_tokens_used()


def make_client(tmp_path, model, budget=10_000):
    return watsonx.WatsonxClient(
        purpose="test", model=model, budget=budget, usage_log=tmp_path / "usage.jsonl"
    )


# --- prompt ----------------------------------------------------------------------------


def test_prompt_contains_component_and_schema():
    messages = build_match_prompt("Foo Bar 1.2 has an XSS.", "bar-core", "foo", "1.2.3")
    assert messages[0]["role"] == "system"
    assert SCHEMA in messages[0]["content"]
    assert [m["role"] for m in messages[1:]] == ["user", "assistant"] * 2 + ["user"]
    question = messages[-1]["content"]
    for field in ("Foo Bar 1.2 has an XSS.", "bar-core", "foo", "1.2.3"):
        assert field in question
    # The worked examples are one yes and one no, as valid JSON.
    answers = [json.loads(m["content"])["affected"] for m in messages if m["role"] == "assistant"]
    assert answers == ["yes", "no"]


def test_missing_vendor_and_version_say_unknown():
    question = build_match_prompt("Something.", "lib", None, None)[-1]["content"]
    assert "Vendor: unknown" in question
    assert "Version: unknown" in question


def test_description_is_truncated():
    long = "word " * 1_000
    assert len(truncate(long)) == MAX_DESCRIPTION_CHARS
    question = build_match_prompt(long, "lib", "v", "1")[-1]["content"]
    assert truncate(long) in question
    assert "word " * 400 not in question


def test_prompt_is_small_without_the_description():
    """About 400 tokens at roughly 4 characters per token."""
    messages = build_match_prompt("", "component", "vendor", "1.0")
    assert sum(len(m["content"]) for m in messages) <= 1_600


# --- client ------------------------------------------------------------------------------


def test_chat_returns_text_and_usage(tmp_path):
    model = FakeModel(replies=['{"affected": "yes"}'])
    text, usage = make_client(tmp_path, model).chat([{"role": "user", "content": "hi"}], 200)
    assert text == '{"affected": "yes"}'
    assert usage == {"prompt_tokens": 100, "completion_tokens": 20}
    assert model.calls[0]["params"] == {"max_tokens": 200, "temperature": 0, "time_limit": 60_000}


def test_slow_call_times_out(tmp_path):
    class SlowModel(FakeModel):
        def chat(self, messages, params):
            time.sleep(0.5)
            return super().chat(messages, params)

    client = watsonx.WatsonxClient(
        model=SlowModel(), usage_log=tmp_path / "usage.jsonl", timeout_s=0.2
    )
    with pytest.raises(TimeoutError):
        client.chat([{"role": "user", "content": "hi"}], 200)


def test_usage_is_counted_and_logged(tmp_path):
    client = make_client(tmp_path, FakeModel())
    client.chat([{"role": "user", "content": "hi"}], 200)
    client.chat([{"role": "user", "content": "hi"}], 200)
    assert watsonx.tokens_used() == 240
    lines = [json.loads(x) for x in (tmp_path / "usage.jsonl").read_text().splitlines()]
    assert len(lines) == 2
    assert lines[0]["purpose"] == "test"
    assert lines[0]["prompt_tokens"] == 100
    assert lines[0]["completion_tokens"] == 20
    assert {"time", "model", "latency_s"} <= lines[0].keys()


def test_budget_guard_raises_before_calling(tmp_path):
    model = FakeModel()
    client = make_client(tmp_path, model, budget=200)
    client.chat([{"role": "user", "content": "hi"}], 200)  # 120 tokens: under budget
    client.chat([{"role": "user", "content": "hi"}], 200)  # 240: now over
    with pytest.raises(watsonx.TokenBudgetExceeded):
        client.chat([{"role": "user", "content": "hi"}], 200)
    assert len(model.calls) == 2


def test_missing_credentials_name_the_variables(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "WATSONX_APIKEY", "")
    monkeypatch.setattr(config, "WATSONX_PROJECT_ID", "")
    client = watsonx.WatsonxClient(usage_log=tmp_path / "usage.jsonl")  # no error yet
    with pytest.raises(watsonx.MissingCredentials, match="WATSONX_APIKEY, WATSONX_PROJECT_ID"):
        client.chat([{"role": "user", "content": "hi"}], 200)
