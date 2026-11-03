"""Context-aware security-header and CORS heuristics."""

import re

import httpx

from .scanner import Finding


def audit_headers(response: httpx.Response, probe_origin: str | None = None) -> list[Finding]:
    headers, url = response.headers, str(response.url)
    findings: list[Finding] = []

    def add(risk: str, title: str, evidence: str, fix: str) -> None:
        findings.append(Finding(risk, title, url, evidence, fix))

    html = "html" in headers.get("content-type", "").lower()
    csp = headers.get("content-security-policy", "")
    directives = {part.strip().split()[0].lower(): part.strip().split()[1:]
                  for part in csp.split(";") if part.strip()}
    if html and not csp:
        add("Medium", "Missing Content-Security-Policy", "HTML response lacks an enforcing CSP.",
            "Deploy a tested nonce- or hash-based Content-Security-Policy.")
    elif html and any(token in directives.get("script-src", directives.get("default-src", []))
                      for token in ("'unsafe-inline'", "'unsafe-eval'", "*")):
        add("Medium", "Permissive script policy", "CSP permits broad or unsafe script execution.",
            "Restrict script sources and remove unsafe script directives where feasible.")
    if html and "frame-ancestors" not in directives and headers.get("x-frame-options", "").upper() not in {"DENY", "SAMEORIGIN"}:
        add("Medium", "Missing framing protection", "No valid X-Frame-Options or CSP frame-ancestors directive.",
            "Set CSP frame-ancestors to an explicit allowlist or 'none'.")
    if response.url.scheme == "https":
        hsts = headers.get("strict-transport-security", "")
        age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
        if age is None or int(age.group(1)) < 31536000:
            add("Low", "Missing or short HSTS policy", "HSTS max-age is absent, invalid or less than one year.",
                "After validating HTTPS coverage, set max-age=31536000 or longer.")
    else:
        add("Medium", "Unencrypted HTTP", "The response was served over HTTP.", "Serve the application over HTTPS.")
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        add("Low", "Missing MIME sniffing protection", "X-Content-Type-Options is not nosniff.",
            "Set X-Content-Type-Options: nosniff and accurate Content-Type headers.")
    allowed = headers.get("access-control-allow-origin", "")
    credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
    if probe_origin and allowed == probe_origin:
        add("High" if credentials else "Medium", "Untrusted CORS origin accepted",
            f"The synthetic untrusted origin was accepted; credentials enabled: {credentials}. Exploitability requires sensitive readable content.",
            "Validate origins against an exact allowlist; disable credentials where unnecessary.")
    elif allowed == "*":
        add("Low", "Public CORS policy", "Wildcard origin permits public reads. Browsers reject wildcard credentialed reads.",
            "Confirm this resource is intentionally public; otherwise restrict allowed origins.")
    return findings
