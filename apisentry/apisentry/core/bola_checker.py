"""Anonymous object-access heuristics, never proof of object ownership failure."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .scanner import Finding, Scanner


def numeric_variant(url: str) -> str | None:
    """Change exactly one object-like numeric selector by one."""
    parts = urlsplit(url)
    match = re.search(r"(?<=/)\d{1,12}(?=/|$)", parts.path)
    if match:
        path = parts.path[:match.start()] + str(int(match.group()) + 1) + parts.path[match.end():]
        return urlunsplit(parts._replace(path=path))
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    for index, (key, value) in enumerate(pairs):
        if re.fullmatch(r"(?:id|.*_id|.*Id)", key) and re.fullmatch(r"\d{1,12}", value):
            pairs[index] = key, str(int(value) + 1)
            return urlunsplit(parts._replace(query=urlencode(pairs)))
    return None


def object_response(response: httpx.Response | None) -> bool:
    if response is None or not response.is_success or "json" not in response.headers.get("content-type", "").lower():
        return False
    try:
        data = response.json()
    except ValueError:
        return False
    return isinstance(data, (dict, list)) and bool(data) and not (
        isinstance(data, dict) and any(key in data for key in ("error", "errors")))


async def check_bola(endpoints: list[str], scanner: Scanner, max_checks: int = 10) -> list[Finding]:
    """Probe original and adjacent identifiers without cookies or credentials.

    Public resources can satisfy this heuristic. Confirmation requires two
    authorized test identities and verified ownership of their test objects.
    """
    findings = []
    checked = 0
    for endpoint in endpoints:
        variant = numeric_variant(endpoint)
        if variant is None or checked >= max_checks:
            continue
        checked += 1
        original = await scanner.fetch(endpoint)
        adjacent = await scanner.fetch(variant)
        if (object_response(original) and object_response(adjacent)
                and original is not None and adjacent is not None
                and original.url != adjacent.url and original.content != adjacent.content):
            findings.append(Finding("Medium", "Potential anonymous object exposure (BOLA review)", endpoint,
                                    "Original and adjacent numeric identifiers returned distinct nonempty JSON without authentication. This does not confirm BOLA.",
                                    "Verify intended public access; test ownership with two authorized identities and enforce object-level authorization."))
    return findings
