"""SHE-38: ask Granite whether a vulnerability description covers an SBOM component.

    messages = build_match_prompt(description, "log4j-core", "apache", "2.14.1")

The answer must be one JSON object matching schemas.granite.MatchVerdict.
"""

import json

MAX_DESCRIPTION_CHARS = 1_500
MATCH_MAX_TOKENS = 200

SCHEMA = (
    '{"affected": "yes|no|unknown", "vendor": string|null, "product": string|null, '
    '"versions": string|null, "confidence": "low|medium|high", "reason": string}'
)

SYSTEM = f"""Decide whether a software component is affected by a vulnerability, using \
only its description. Reply with one JSON object only:
{SCHEMA}
affected: "yes" if the description names this product and the version is in the affected \
range; "no" if it names another product, or the version is outside the range; "unknown" \
if the versions are not stated.
vendor, product, versions: as the description states them, or null.
reason: 25 words or fewer."""

# Two short worked examples: one "yes", one "no".
EXAMPLES = [
    (
        "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features allow remote code execution.",
        "log4j-core",
        "apache",
        "2.14.1",
        {
            "affected": "yes",
            "vendor": "Apache",
            "product": "Log4j2",
            "versions": "2.0-beta9 through 2.15.0",
            "confidence": "high",
            "reason": "2.14.1 is in the affected range.",
        },
    ),
    (
        "A buffer overflow in Zyxel NAS326 firmware before V5.21 allows code execution.",
        "nginx",
        "f5",
        "1.24.0",
        {
            "affected": "no",
            "vendor": "Zyxel",
            "product": "NAS326 firmware",
            "versions": "before V5.21",
            "confidence": "high",
            "reason": "The description is about Zyxel firmware, not nginx.",
        },
    ),
]


def truncate(description: str, limit: int = MAX_DESCRIPTION_CHARS) -> str:
    description = " ".join(description.split())
    return description if len(description) <= limit else description[: limit - 3] + "..."


def user_message(description: str, component_name: str, vendor: str | None, version: str | None):
    return (
        f"Description: {truncate(description)}\n"
        f"Component: {component_name}\n"
        f"Vendor: {vendor or 'unknown'}\n"
        f"Version: {version or 'unknown'}"
    )


def build_match_prompt(
    description: str, component_name: str, vendor: str | None, version: str | None
) -> list[dict]:
    """Chat messages: the rules, two worked examples, then the question."""
    messages = [{"role": "system", "content": SYSTEM}]
    for ex_description, ex_name, ex_vendor, ex_version, answer in EXAMPLES:
        messages.append(
            {
                "role": "user",
                "content": user_message(ex_description, ex_name, ex_vendor, ex_version),
            }
        )
        messages.append({"role": "assistant", "content": json.dumps(answer)})
    messages.append(
        {"role": "user", "content": user_message(description, component_name, vendor, version)}
    )
    return messages
