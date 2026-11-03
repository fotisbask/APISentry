"""Offline behavioral and reporting regression tests."""

import tempfile
import unittest
from pathlib import Path

import httpx

from apisentry.core.bola_checker import check_bola, numeric_variant
from apisentry.core.headers import audit_headers
from apisentry.core.js_parser import discover_javascript
from apisentry.core.scanner import Finding, ScanResult, Scanner
from apisentry.reporters.html_report import render_report


class AssessmentTests(unittest.IsolatedAsyncioTestCase):
    async def test_scope_redirect_budget_and_cookies(self):
        seen = []

        def handle(request):
            seen.append(request)
            if request.url.path == "/":
                return httpx.Response(302, headers={"location": "/next", "set-cookie": "session=secret"})
            return httpx.Response(302, headers={"location": "https://other.test/"})

        async with Scanner("https://example.test", delay=0, transport=httpx.MockTransport(handle)) as scanner:
            self.assertIsNone(await scanner.fetch(scanner.target))
            self.assertEqual(scanner.requests, 2)
            self.assertEqual(seen[-1].headers.get("cookie"), "")
            self.assertTrue(scanner.errors)

    async def test_size_and_budget(self):
        transport = httpx.MockTransport(lambda _: httpx.Response(200, content=b"oversized"))
        async with Scanner("https://example.test", delay=0, max_bytes=3,
                           max_requests=1, transport=transport) as scanner:
            self.assertIsNone(await scanner.fetch(scanner.target))
            self.assertIsNone(await scanner.fetch(scanner.target))
            self.assertEqual(scanner.requests, 1)
            self.assertEqual(len(scanner.errors), 2)

    async def test_discovery_and_redaction(self):
        secret = "aVeryPrivateSecret123456"
        transport = httpx.MockTransport(lambda _: httpx.Response(200, text='fetch("/api/users/12")'))
        async with Scanner("https://example.test", delay=0, transport=transport) as scanner:
            response = httpx.Response(200, headers={"content-type": "text/html"},
                text=f'<script>const api_key="{secret}";</script><script src="/app.js"></script>',
                request=httpx.Request("GET", scanner.target))
            endpoints, findings = await discover_javascript(response, scanner)
            self.assertEqual(endpoints, ["https://example.test/api/users/12"])
            self.assertEqual(len(findings), 1)
            self.assertNotIn(secret, repr(findings))

    async def test_bola_distinct_json_and_denial(self):
        def handle(request):
            return httpx.Response(200, json={"id": request.url.path.rsplit("/", 1)[1]})
        async with Scanner("https://example.test", delay=0, transport=httpx.MockTransport(handle)) as scanner:
            findings = await check_bola(["https://example.test/api/users/1"], scanner)
            self.assertEqual(len(findings), 1)
            self.assertIn("does not confirm", findings[0].evidence)
        async with Scanner("https://example.test", delay=0,
                           transport=httpx.MockTransport(lambda _: httpx.Response(403))) as scanner:
            self.assertEqual(await check_bola(["https://example.test/api/users/1"], scanner), [])


class AnalysisTests(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(numeric_variant("https://x.test/api/users/9"), "https://x.test/api/users/10")
        self.assertEqual(numeric_variant("https://x.test/api/users?id=9"), "https://x.test/api/users?id=10")
        self.assertIsNone(numeric_variant("https://x.test/api/users?limit=9"))

    def test_cors_and_html_context(self):
        probe = "https://untrusted.invalid"
        response = httpx.Response(200, headers={"content-type": "application/json",
            "access-control-allow-origin": probe, "access-control-allow-credentials": "true"},
            request=httpx.Request("GET", "https://example.test"))
        findings = audit_headers(response, probe)
        self.assertTrue(any(f.risk == "High" for f in findings))
        self.assertFalse(any("framing" in f.title or "Content-Security" in f.title for f in findings))

    def test_report_escaping_and_query_redaction(self):
        result = ScanResult("https://example.test/?token=private-value")
        result.findings.append(Finding("High", "<script>alert(1)</script>", result.target, "evidence", "fix"))
        with tempfile.TemporaryDirectory() as directory:
            report = render_report(result, Path(directory) / "report.html").read_text(encoding="utf-8")
        self.assertNotIn("private-value", report)
        self.assertNotIn("<script>alert", report)
        self.assertIn("&lt;script&gt;", report)


if __name__ == "__main__":
    unittest.main()
