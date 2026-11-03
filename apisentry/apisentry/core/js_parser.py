"""Bounded JavaScript discovery and heuristic endpoint/secret extraction."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from .scanner import Finding, Scanner

ENDPOINT = re.compile(r'''["'`]((?:https?://[^\s"'`<>]+)?/(?:api|rest|graphql)(?:[/?][^\s"'`<>]*)?)["'`]''', re.I)
SECRETS = (
    ("AWS access key identifier", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Assigned API key or token", re.compile(r'''["']?(?:api[_-]?key|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']([^"'\s]{16,})["']''', re.I)),
)


def parse_javascript(text: str, source: str, scanner: Scanner) -> tuple[set[str], list[Finding]]:
    endpoints: set[str] = set()
    for match in ENDPOINT.finditer(text):
        value = match.group(1)
        if any(char in value for char in ("${", "{", "}", "\\")):
            continue
        url = urljoin(source, value)
        if scanner.in_scope(url):
            endpoints.add(url)
    findings = []
    for name, pattern in SECRETS:
        if pattern.search(text):
            findings.append(Finding("High" if name == "Private key material" else "Medium",
                                    f"Potential secret: {name}", source,
                                    "Pattern matched in JavaScript; value redacted. Validity has not been tested.",
                                    "Review locally; revoke exposed credentials and move secrets to server-side storage."))
    return endpoints, findings


async def discover_javascript(response: httpx.Response, scanner: Scanner,
                              max_scripts: int = 20) -> tuple[list[str], list[Finding]]:
    source = str(response.url)
    content_type = response.headers.get("content-type", "").lower()
    if "javascript" in content_type:
        endpoints, findings = parse_javascript(response.text, source, scanner)
        return sorted(endpoints), findings
    if "html" not in content_type:
        return [], []
    soup = BeautifulSoup(response.text, "html.parser")
    base_tag = soup.find("base", href=True)
    base = urljoin(source, str(base_tag["href"])) if base_tag else source
    endpoints: set[str] = set()
    findings: list[Finding] = []
    external: set[str] = set()
    for tag in soup.find_all("script", limit=max_scripts):
        if tag.get("src"):
            url = urljoin(base, str(tag["src"]))
            if scanner.in_scope(url):
                external.add(url)
        else:
            found, issues = parse_javascript(tag.get_text(), base, scanner)
            endpoints.update(found)
            findings.extend(issues)
    responses = await asyncio.gather(*(scanner.fetch(url) for url in sorted(external)))
    for script in responses:
        if script is not None and script.is_success:
            found, issues = parse_javascript(script.text, str(script.url), scanner)
            endpoints.update(found)
            findings.extend(issues)
    return sorted(endpoints), findings
