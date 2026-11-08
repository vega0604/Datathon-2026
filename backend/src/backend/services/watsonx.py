"""SHE-38: Granite on watsonx, with a token budget and a usage log.

    client = WatsonxClient(purpose="quality")
    text, usage = client.chat(messages, max_tokens=200)

Every call is logged to outputs/logs/watsonx_usage.jsonl. Once this process has used
WATSONX_TOKEN_BUDGET tokens, the next call raises TokenBudgetExceeded before it is sent.
Importing this module never needs credentials; the watsonx model is built on first use.
"""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from backend.core import config

USAGE_LOG = config.LOGS_DIR / "watsonx_usage.jsonl"
CREDENTIAL_VARIABLES = ("WATSONX_APIKEY", "WATSONX_PROJECT_ID", "WATSONX_URL")
TIMEOUT_S = 60  # per call; a slower call raises TimeoutError

# Calls run on a worker thread so a hung connection can be abandoned after TIMEOUT_S.
_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="watsonx")


class TokenBudgetExceeded(RuntimeError):
    pass


class MissingCredentials(RuntimeError):
    pass


# Tokens used by every client in this process, checked against the budget.
_tokens_used = 0


def tokens_used() -> int:
    return _tokens_used


def reset_tokens_used() -> None:
    global _tokens_used
    _tokens_used = 0


def _add_tokens(n: int) -> None:
    global _tokens_used
    _tokens_used += n


def build_model():
    """The ibm_watsonx_ai chat model, from backend/.env settings."""
    missing = [name for name in CREDENTIAL_VARIABLES if not getattr(config, name)]
    if missing:
        raise MissingCredentials(
            f"Missing watsonx settings: {', '.join(missing)}. Add them to backend/.env "
            "(see .env.example)."
        )
    from ibm_watsonx_ai import Credentials
    from ibm_watsonx_ai.foundation_models import ModelInference

    return ModelInference(
        model_id=config.WATSONX_MODEL_ID,
        project_id=config.WATSONX_PROJECT_ID,
        credentials=Credentials(url=config.WATSONX_URL, api_key=config.WATSONX_APIKEY),
    )


class WatsonxClient:
    def __init__(
        self,
        purpose: str = "general",
        model=None,
        budget: int | None = None,
        usage_log: Path | None = None,
        timeout_s: float = TIMEOUT_S,
    ):
        """`model` is anything with a `chat(messages, params)` method returning a watsonx
        chat response; tests pass a fake. By default it is built on the first call."""
        self.purpose = purpose
        self._model = model
        self.budget = config.WATSONX_TOKEN_BUDGET if budget is None else budget
        self.usage_log = usage_log or USAGE_LOG
        self.timeout_s = timeout_s

    @property
    def model(self):
        if self._model is None:
            self._model = build_model()
        return self._model

    def chat(
        self, messages: list[dict], max_tokens: int, temperature: float = 0
    ) -> tuple[str, dict]:
        """Send `messages`; return the reply text and its token usage."""
        if _tokens_used >= self.budget:
            raise TokenBudgetExceeded(
                f"{_tokens_used:,} watsonx tokens used; the budget is {self.budget:,} "
                "(WATSONX_TOKEN_BUDGET)."
            )
        params = {
            "max_tokens": max_tokens,
            "temperature": temperature,
            "time_limit": int(self.timeout_s * 1000),  # server side, in milliseconds
        }
        start = time.perf_counter()
        future = _pool.submit(self.model.chat, messages=messages, params=params)
        # Hard client-side limit: the library's own HTTP timeout is 30 minutes.
        response = future.result(timeout=self.timeout_s)
        latency = time.perf_counter() - start
        text = response["choices"][0]["message"]["content"] or ""
        raw = response.get("usage") or {}
        usage = {
            "prompt_tokens": int(raw.get("prompt_tokens", 0)),
            "completion_tokens": int(raw.get("completion_tokens", 0)),
        }
        _add_tokens(usage["prompt_tokens"] + usage["completion_tokens"])
        self._log(usage, latency)
        return text, usage

    def _log(self, usage: dict, latency: float) -> None:
        self.usage_log.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "time": datetime.now(UTC).isoformat(timespec="seconds"),
            "model": config.WATSONX_MODEL_ID,
            "purpose": self.purpose,
            **usage,
            "latency_s": round(latency, 3),
        }
        with self.usage_log.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
