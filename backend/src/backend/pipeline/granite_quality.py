"""SHE-40: how well does the Granite match check answer on a fixed sample of 40 pairs?

    uv run python -m backend.pipeline.granite_quality

Sample (fixed seed): NIST-analyzed vulnerabilities published in 2025 that have vulnerable
product rows. 20 true pairs (a vulnerability and one of its own products, at its exact
version or a version inside its range) and 20 false pairs (a vulnerability and a product
from a different vendor, taken from another vulnerability). Uses about 25-30k watsonx
tokens. Writes outputs/logs/granite_quality.json and granite_quality_verdicts.csv.
"""

import csv
import json
import random
from collections import Counter

from backend.core.config import LOGS_DIR, WATSONX_MODEL_ID
from backend.db.warehouse import connect
from backend.services import watsonx
from backend.services.match_check import Component, check_match

SEED = 40
PAIRS_PER_KIND = 20
MIN_VALID_JSON_RATE = 0.95
VERDICTS_CSV = LOGS_DIR / "granite_quality_verdicts.csv"
CSV_COLUMNS = [
    "cve_id", "truth", "vendor", "product", "version", "product_from", "affected",
    "confidence", "vendor_said", "product_said", "versions", "reason", "error", "calls",
]  # fmt: skip

# A version to ask about: the exact version, else the start or end of an inclusive range.
PRODUCT_ROWS_SQL = """
    SELECT cve_id, vendor, product, version
    FROM (
        SELECT
            a.cve_id, a.vendor, a.product,
            CASE
                WHEN coalesce(a.version, '') NOT IN ('', '*', '-') THEN a.version
                WHEN a.version_start_including IS NOT NULL THEN a.version_start_including
                WHEN a.version_end_including IS NOT NULL THEN a.version_end_including
            END AS version
        FROM clean.affected_products AS a
        JOIN vulnerabilities AS v USING (cve_id)
        WHERE a.vulnerable = 'Y'
          AND v.nvd_status = 'Analyzed'
          AND v.published >= DATE '2025-01-01' AND v.published < DATE '2026-01-01'
    )
    WHERE version IS NOT NULL
    ORDER BY cve_id, vendor, product, version
"""


def sample_pairs(rows: list[tuple], seed: int = SEED, n: int = PAIRS_PER_KIND) -> list[dict]:
    """rows: (cve_id, vendor, product, version). Returns n true and n false pairs."""
    by_cve: dict[str, list[tuple]] = {}
    for row in rows:
        by_cve.setdefault(row[0], []).append(row)
    rng = random.Random(seed)
    cves = sorted(by_cve)
    rng.shuffle(cves)
    pairs = []
    for cve in cves[:n]:
        _, vendor, product, version = rng.choice(by_cve[cve])
        pairs.append(
            {"cve_id": cve, "truth": True, "vendor": vendor, "product": product, "version": version}
        )
    for cve in cves[n : 2 * n]:
        own_vendors = {r[1] for r in by_cve[cve]}
        while True:
            other = rng.choice(cves)
            _, vendor, product, version = rng.choice(by_cve[other])
            if other != cve and vendor not in own_vendors:
                break
        pairs.append(
            {
                "cve_id": cve,
                "truth": False,
                "vendor": vendor,
                "product": product,
                "version": version,
                "product_from": other,
            }
        )
    return pairs


class CountingClient:
    """Counts chat calls, so the first-try valid-JSON rate excludes retries."""

    def __init__(self, client):
        self.client = client
        self.calls = 0

    def chat(self, messages, max_tokens, temperature=0):
        self.calls += 1
        return self.client.chat(messages, max_tokens, temperature)


def confusion(results: list[dict]) -> dict[str, dict[str, int]]:
    counts = Counter((r["truth"], r["affected"]) for r in results)
    return {
        truth_name: {answer: counts[(truth, answer)] for answer in ("yes", "no", "unknown")}
        for truth, truth_name in ((True, "true_pairs"), (False, "false_pairs"))
    }


def main() -> None:
    con = connect()
    pairs = sample_pairs(con.execute(PRODUCT_ROWS_SQL).fetchall())
    descriptions = dict(
        con.execute(
            "SELECT cve_id, description FROM vulnerabilities WHERE list_contains(?, cve_id)",
            [[p["cve_id"] for p in pairs]],
        ).fetchall()
    )
    client = CountingClient(watsonx.WatsonxClient(purpose="quality"))
    results = []
    for i, pair in enumerate(pairs, 1):
        before = client.calls
        component = Component(pair["product"], pair["vendor"], pair["version"])
        verdict = check_match(client, descriptions[pair["cve_id"]], component)
        said = verdict.model_dump()
        said["vendor_said"], said["product_said"] = said.pop("vendor"), said.pop("product")
        results.append({**pair, **said, "calls": client.calls - before})
        print(
            f"{i:>2}/{len(pairs)} {pair['cve_id']:<16} truth={pair['truth']!s:<5} "
            f"-> {verdict.affected:<7} ({client.calls - before} call)",
            flush=True,
        )

    first_try = sum(1 for r in results if r["calls"] == 1)
    report = {
        "model": WATSONX_MODEL_ID,
        "pairs": len(results),
        "valid_json_rate": first_try / len(results),
        "retries": sum(1 for r in results if r["calls"] > 1),
        "errors": sum(1 for r in results if r["error"]),
        "confusion": confusion(results),
        "tokens": watsonx.tokens_used(),
        "min_valid_json_rate": MIN_VALID_JSON_RATE,
    }
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "granite_quality.json").write_text(json.dumps(report, indent=2) + "\n")
    with VERDICTS_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    print(
        f"\nvalid JSON (first try) {report['valid_json_rate']:.0%}, retries "
        f"{report['retries']}, errors {report['errors']}, tokens {report['tokens']:,}"
    )
    print(f"{'':<12} {'yes':>4} {'no':>4} {'unknown':>8}")
    for name, row in report["confusion"].items():
        print(f"{name:<12} {row['yes']:>4} {row['no']:>4} {row['unknown']:>8}")


if __name__ == "__main__":
    main()
