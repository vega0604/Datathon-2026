"""Version comparison and affected-range checks. Pure functions."""

import re
from functools import lru_cache

from packaging.version import InvalidVersion, Version

# Product rows also have an `update` column (e.g. r1, h3). It is ignored on purpose:
# SBOM versions rarely carry it, so comparing it would mostly produce false negatives.


def _loose_key(v: str) -> list[tuple[int, int | str]]:
    out: list[tuple[int, int | str]] = []
    for tok in re.findall(r"\d+|[a-z]+", v.lower()):
        out.append((1, int(tok)) if tok.isdigit() else (0, tok))
    return out


@lru_cache(maxsize=65536)
def _pep440(v: str) -> Version | None:
    try:
        return Version(v)
    except InvalidVersion:
        return None


@lru_cache(maxsize=65536)
def _loose_cached(v: str) -> tuple:
    return tuple(_loose_key(v))


def compare(a: str, b: str) -> int:
    """-1, 0 or 1. Uses PEP 440 when both parse, else a loose numbers-and-letters key."""
    va, vb = _pep440(a), _pep440(b)
    if va is None or vb is None:
        va, vb = _loose_cached(a), _loose_cached(b)
    return (va > vb) - (va < vb)


def _blank(v: str | None) -> bool:
    return v is None or v.strip() in ("", "*", "-")


def in_range(
    version: str | None,
    exact: str | None,
    start_inc: str | None,
    start_exc: str | None,
    end_inc: str | None,
    end_exc: str | None,
) -> bool | None:
    """True if the version is affected, False if not, None if it cannot be told."""
    have_version = not _blank(version)
    if not _blank(exact):
        return compare(version, exact) == 0 if have_version else None
    bounds = [start_inc, start_exc, end_inc, end_exc]
    if all(_blank(b) for b in bounds):
        return True
    if not have_version:
        return None
    if not _blank(start_inc) and compare(version, start_inc) < 0:
        return False
    if not _blank(start_exc) and compare(version, start_exc) <= 0:
        return False
    if not _blank(end_inc) and compare(version, end_inc) > 0:
        return False
    return _blank(end_exc) or compare(version, end_exc) < 0
