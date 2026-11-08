"""Unit tests for SHE-39 output validation, with a fake client: no network."""

import json

from backend.schemas.granite import MatchVerdict
from backend.services.match_check import Component, check_match, parse_verdict

VALID = {
    "affected": "yes",
    "vendor": "Apache",
    "product": "Log4j2",
    "versions": "2.0-beta9 through 2.15.0",
    "confidence": "high",
    "reason": "In range.",
}
COMPONENT = Component("log4j-core", "apache", "2.14.1")


class FakeClient:
    """Replies with the given texts in order and records every message list it gets."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.sent = []

    def chat(self, messages, max_tokens, temperature=0):
        self.sent.append(messages)
        return self.replies[len(self.sent) - 1], {"prompt_tokens": 1, "completion_tokens": 1}


def test_valid_json():
    client = FakeClient(json.dumps(VALID))
    verdict = check_match(client, "Log4j2 ...", COMPONENT)
    assert verdict == MatchVerdict(**VALID)
    assert not verdict.error
    assert len(client.sent) == 1


def test_fenced_json_with_chatter():
    reply = f"Sure, here it is:\n```json\n{json.dumps(VALID)}\n```\nHope that helps."
    client = FakeClient(reply)
    assert check_match(client, "Log4j2 ...", COMPONENT).affected == "yes"
    assert len(client.sent) == 1


def test_invalid_then_valid_retries_once():
    client = FakeClient('{"affected": "maybe"}', json.dumps(VALID))
    verdict = check_match(client, "Log4j2 ...", COMPONENT)
    assert verdict.affected == "yes"
    assert len(client.sent) == 2
    follow_up = client.sent[1][-1]["content"]
    assert "affected" in follow_up  # the validation error is passed back
    assert "JSON object only" in follow_up


def test_invalid_twice_gives_the_error_verdict():
    client = FakeClient("I think so.", "Yes, it is affected.")
    verdict = check_match(client, "Log4j2 ...", COMPONENT)
    assert verdict.error
    assert verdict.affected == "unknown"
    assert verdict.confidence == "low"
    assert verdict.reason == "invalid model output"
    assert len(client.sent) == 2


def test_parse_verdict_trims_a_long_reason():
    long = {**VALID, "reason": "word " * 40}
    assert len(parse_verdict(json.dumps(long)).reason.split()) == 25
