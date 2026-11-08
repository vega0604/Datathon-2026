"""SHE-37: how fast are Granite embeddings on this CPU, and what does a watsonx call cost?

    uv run python -m backend.pipeline.granite_benchmark [--skip-watsonx] [--write-env]

Embeddings: encodes the same 1,000 in-scope descriptions (fixed sample) with each
backend and length in COMBINATIONS, checks each gives the same vectors as torch at that
length (mean cosine >= 0.99), and projects the hours for every in-scope vulnerability.
--write-env saves the fastest passing combination to backend/.env.
watsonx: 3 small chat calls, with latency and token usage, projected to 300 match checks.
Writes outputs/logs/granite_benchmark.json.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np

from backend.core.config import (
    BACKEND_DIR,
    EMBEDDING_MODEL_ID,
    FEATURES_DIR,
    LOGS_DIR,
    WATSONX_MODEL_ID,
)
from backend.db.warehouse import connect

SAMPLE_SIZE = 1_000
SAMPLE_SEED = "she-37"
BATCH_SIZE = 32
PROJECTED_ROWS = 138_000
MIN_COSINE = 0.99
WATSONX_CALLS = 3
WATSONX_TIMEOUT_S = 60
MATCH_CHECKS = 300

# (name, backend, max_seq_length, OpenVINO device or None). Torch at each length is the
# reference the others are compared with, so it runs first.
COMBINATIONS = [
    ("torch-512", "torch", 512, None),
    ("torch-256", "torch", 256, None),
    ("onnx-256", "onnx", 256, None),
    ("openvino-256", "openvino", 256, None),
    ("openvino-gpu-256", "openvino", 256, "GPU"),
]


def phase(message: str) -> None:
    """Print a progress line straight away, so a slow step shows where it is."""
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


# --- pure helpers (unit-tested) ------------------------------------------------------


def project_minutes(per_second: float, items: int) -> float:
    """Minutes to process `items` at `per_second` items per second."""
    if per_second <= 0:
        raise ValueError("per_second must be positive")
    return items / per_second / 60


def project_tokens(usages: list[tuple[int, int]], calls: int = MATCH_CHECKS) -> dict:
    """Mean prompt and completion tokens per call, and the total for `calls` calls."""
    if not usages:
        raise ValueError("no usage to project from")
    prompt = sum(p for p, _ in usages) / len(usages)
    completion = sum(c for _, c in usages) / len(usages)
    return {
        "mean_prompt_tokens": prompt,
        "mean_completion_tokens": completion,
        "mean_tokens_per_call": prompt + completion,
        "calls": calls,
        "projected_tokens": round((prompt + completion) * calls),
    }


def mean_cosine(a: np.ndarray, b: np.ndarray) -> float:
    """Mean cosine similarity between matching rows of a and b."""
    a = a / np.linalg.norm(a, axis=1, keepdims=True)
    b = b / np.linalg.norm(b, axis=1, keepdims=True)
    return float((a * b).sum(axis=1).mean())


def fastest_passing(runs: list[dict]) -> dict | None:
    """The fastest run that finished and matched torch."""
    passing = [r for r in runs if r.get("passed")]
    return max(passing, key=lambda r: r["desc_per_second"]) if passing else None


def set_env_values(text: str, values: dict[str, str]) -> str:
    """Set KEY=value lines in .env text, replacing existing keys and appending new ones."""
    for key, value in values.items():
        line = f"{key}={value}"
        pattern = re.compile(rf"^[ \t]*{re.escape(key)}[ \t]*=.*$", re.MULTILINE)
        if pattern.search(text):
            text = pattern.sub(line, text)
        else:
            text = text.rstrip("\n") + ("\n" if text.strip() else "") + line + "\n"
    return text


# --- inputs ------------------------------------------------------------------------


def in_scope_sql() -> str:
    """Distinct population vulnerabilities plus every KEV entry, with a description."""
    population = (FEATURES_DIR / "population.parquet").as_posix()
    return f"""
        SELECT v.cve_id, v.description
        FROM (
            SELECT cve_id FROM read_parquet('{population}')
            UNION
            SELECT cve_id FROM known_exploited
        ) AS s
        JOIN vulnerabilities AS v USING (cve_id)
        WHERE trim(coalesce(v.description, '')) <> ''
    """


# --- embeddings --------------------------------------------------------------------


GPU_PROBE = (
    "from backend.services.embedding_model import load_embedding_model\n"
    "load_embedding_model(backend='openvino', max_seq_length=256, device='{device}')"
    ".encode(['probe'])\n"
)


def device_usable(device: str) -> str | None:
    """Try OpenVINO on `device` in a child process, because a driver failure can crash
    the interpreter instead of raising. Returns None if it works, else why not."""
    try:
        done = subprocess.run(
            [sys.executable, "-c", GPU_PROBE.format(device=device)],
            check=False,
            capture_output=True,
            text=True,
            timeout=900,
        )
    except subprocess.TimeoutExpired:
        return f"OpenVINO on {device} did not finish a 1-text probe in 15 minutes"
    if done.returncode != 0:
        last = (done.stderr.strip().splitlines() or ["no error message"])[-1]
        return f"OpenVINO on {device} crashed (exit code {done.returncode}): {last}"
    return None


def time_combination(texts: list[str], backend: str, length: int, device: str | None):
    from backend.services.embedding_model import load_embedding_model

    if device is not None:
        problem = device_usable(device)
        if problem:
            raise RuntimeError(problem)

    model = load_embedding_model(backend=backend, max_seq_length=length, device=device)
    model.encode(texts[:BATCH_SIZE], batch_size=BATCH_SIZE, normalize_embeddings=True)  # warm-up
    start = time.perf_counter()
    vectors = model.encode(texts, batch_size=BATCH_SIZE, normalize_embeddings=True)
    return np.asarray(vectors, dtype=np.float32), time.perf_counter() - start


def benchmark_embeddings(con) -> dict:
    phase("sampling in-scope descriptions")
    texts = [
        row[0]
        for row in con.execute(
            f"""
            SELECT description FROM ({in_scope_sql()})
            ORDER BY md5(cve_id || '{SAMPLE_SEED}') LIMIT {SAMPLE_SIZE}
            """
        ).fetchall()
    ]
    reference: dict[int, np.ndarray] = {}  # torch vectors by max_seq_length
    runs = []
    for name, backend, length, device in COMBINATIONS:
        phase(f"{name}: loading and encoding {len(texts):,} descriptions at batch {BATCH_SIZE}")
        run = {"name": name, "backend": backend, "max_seq_length": length, "device": device}
        try:
            vectors, seconds = time_combination(texts, backend, length, device)
        except Exception as error:  # noqa: BLE001 - an unusable backend or device is skipped
            run.update(passed=False, error=f"{type(error).__name__}: {error}"[:300])
            phase(f"{name}: skipped ({run['error'][:120]})")
            runs.append(run)
            continue
        if backend == "torch":
            reference[length] = vectors
        cosine = mean_cosine(vectors, reference[length]) if length in reference else None
        per_second = len(texts) / seconds
        run.update(
            seconds=round(seconds, 2),
            desc_per_second=round(per_second, 2),
            projected_hours=round(project_minutes(per_second, PROJECTED_ROWS) / 60, 2),
            cosine_vs_torch=None if cosine is None else round(cosine, 5),
            passed=cosine is not None and cosine >= MIN_COSINE,
        )
        phase(f"{name}: {per_second:,.1f} desc/s, cosine vs torch {cosine:.5f}")
        runs.append(run)
    best = fastest_passing(runs)
    return {
        "model": EMBEDDING_MODEL_ID,
        "sample": len(texts),
        "probe_description": texts[0],
        "batch_size": BATCH_SIZE,
        "projected_rows": PROJECTED_ROWS,
        "min_cosine": MIN_COSINE,
        "runs": runs,
        "chosen": None if best is None else best["name"],
    }


def write_env(best: dict, env_path: Path = BACKEND_DIR / ".env") -> None:
    """Save the chosen combination to backend/.env without printing anything else in it."""
    values = {
        "EMBEDDING_BACKEND": best["backend"],
        "EMBEDDING_MAX_SEQ_LENGTH": str(best["max_seq_length"]),
        "EMBEDDING_BATCH_SIZE": str(BATCH_SIZE),
    }
    text = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
    env_path.write_text(set_env_values(text, values), encoding="utf-8")
    phase(f"wrote {', '.join(f'{k}={v}' for k, v in values.items())} to {env_path.name}")


# --- watsonx -----------------------------------------------------------------------


def probe_messages(description: str) -> list[dict]:
    """A match-check-sized question about a real description."""
    return [
        {
            "role": "system",
            "content": "Decide only from the vulnerability description. Answer with one JSON "
            'object: {"affected": "yes|no|unknown", "reason": "<= 25 words"}.',
        },
        {
            "role": "user",
            "content": f"Description: {description[:1500]}\n\n"
            "Component: openssl 3.0.7 (vendor: openssl). Is it affected?",
        },
    ]


def benchmark_watsonx(description: str) -> dict:
    from ibm_watsonx_ai import Credentials
    from ibm_watsonx_ai.foundation_models import ModelInference

    from backend.core.config import WATSONX_APIKEY, WATSONX_PROJECT_ID, WATSONX_URL

    phase(f"connecting to watsonx ({WATSONX_MODEL_ID})")
    model = ModelInference(
        model_id=WATSONX_MODEL_ID,
        project_id=WATSONX_PROJECT_ID,
        credentials=Credentials(url=WATSONX_URL, api_key=WATSONX_APIKEY),
    )
    params = {"max_tokens": 200, "temperature": 0, "time_limit": WATSONX_TIMEOUT_S * 1000}
    calls = []
    pool = ThreadPoolExecutor(max_workers=1)
    for i in range(WATSONX_CALLS):
        phase(f"watsonx call {i + 1}/{WATSONX_CALLS}")
        start = time.perf_counter()
        future = pool.submit(model.chat, messages=probe_messages(description), params=params)
        # Hard client-side limit: the library's own HTTP timeout is 30 minutes.
        response = future.result(timeout=WATSONX_TIMEOUT_S)
        usage = response.get("usage", {})
        calls.append(
            {
                "latency_s": round(time.perf_counter() - start, 2),
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
            }
        )
    pool.shutdown(wait=False)
    usages = [(c["prompt_tokens"], c["completion_tokens"]) for c in calls]
    return {
        "model": WATSONX_MODEL_ID,
        "calls": calls,
        "mean_latency_s": round(sum(c["latency_s"] for c in calls) / len(calls), 2),
        "projection": project_tokens(usages),
    }


def print_embeddings(result: dict) -> None:
    print(
        f"\nEmbeddings ({result['model']}, {result['sample']:,} descriptions, batch "
        f"{result['batch_size']})"
    )
    print(f"{'combination':<18} {'desc/s':>8} {'hours/138k':>11} {'cosine':>8}  result")
    for run in result["runs"]:
        if "error" in run:
            print(f"{run['name']:<18} {'-':>8} {'-':>11} {'-':>8}  skipped: {run['error'][:60]}")
            continue
        cosine = "-" if run["cosine_vs_torch"] is None else f"{run['cosine_vs_torch']:.4f}"
        verdict = "pass" if run["passed"] else "excluded"
        print(
            f"{run['name']:<18} {run['desc_per_second']:>8} {run['projected_hours']:>11} "
            f"{cosine:>8}  {verdict}"
        )
    print(f"Fastest passing: {result['chosen']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-watsonx", action="store_true", help="embeddings only")
    parser.add_argument(
        "--write-env", action="store_true", help="save the fastest passing settings to .env"
    )
    args = parser.parse_args()
    if not (FEATURES_DIR / "population.parquet").exists():
        raise SystemExit("No population. Run `uv run python -m backend.pipeline.population` first.")

    phase("connecting to the warehouse")
    result = {"embeddings": benchmark_embeddings(connect())}
    probe = result["embeddings"].pop("probe_description")
    print_embeddings(result["embeddings"])
    best = fastest_passing(result["embeddings"]["runs"])
    if args.write_env and best is not None:
        write_env(best)
    if not args.skip_watsonx:
        result["watsonx"] = benchmark_watsonx(probe)
        w = result["watsonx"]
        print(f"\nwatsonx ({w['model']})")
        print(f"{'call':>5} {'latency s':>10} {'prompt':>7} {'completion':>11}")
        for i, call in enumerate(w["calls"], 1):
            print(
                f"{i:>5} {call['latency_s']:>10} {call['prompt_tokens']:>7} "
                f"{call['completion_tokens']:>11}"
            )
        p = w["projection"]
        print(f"Projected tokens for {p['calls']} match checks: {p['projected_tokens']:,}")
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "granite_benchmark.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
