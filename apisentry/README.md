# APISentry

APISentry is a Python 3.11+ CLI for authorized front-facing web and REST API assessments. It inspects browser security headers, tests acceptance of a synthetic CORS origin, discovers literal API endpoints in JavaScript, identifies potential embedded credentials, and optionally probes anonymous access to adjacent numeric object identifiers.

## Installation

Run these commands from this directory:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py --help
```

On macOS/Linux, activate with `source .venv/bin/activate`. Runtime dependencies are bounded to compatible major versions; production environments should generate and maintain a hash-locked dependency set using their deployment tooling.

## Usage

For a reproducible offline demonstration, run `python demo_local.py`.
It starts a temporary server on `127.0.0.1`, scans synthetic data with the real
CLI, writes `reports/local-demo.html`, and stops the server automatically.
Expected output: High 1, Medium 5, Low 1, five requests and zero coverage errors.
These are deliberately introduced lab weaknesses, not findings about your PC.

```powershell
python main.py --target https://app.example.com --output reports/assessment.html
python main.py --target https://app.example.com --bola --max-bola-checks 5
python main.py --target https://app.example.com --concurrency 2 --delay 0.5 --max-requests 50
```

Use only against systems within your authorized assessment scope. All requests use GET, but poorly designed applications may still attach side effects to GET endpoints. Review scope before enabling active ID probes.

| Option | Default | Purpose |
| --- | --- | --- |
| `--target` | Required | Absolute HTTP(S) starting URL |
| `--output` | `apisentry-report.html` | HTML destination; existing file is overwritten |
| `--timeout` | 10 | HTTP phase timeout in seconds |
| `--concurrency` | 4 | Maximum concurrent requests |
| `--delay` | 0.1 | Minimum seconds between global request starts |
| `--max-requests` | 100 | Shared request budget, including redirects |
| `--max-bytes` | 2000000 | Maximum decoded response body |
| `--max-scripts` | 20 | Maximum script tags examined |
| `--bola` | Disabled | Enable anonymous original/adjacent ID comparisons |
| `--max-bola-checks` | 10 | Maximum endpoint pairs checked |

Exit codes: `0` means no findings or coverage errors; `1` means findings; `2` means invalid input, output failure, or incomplete coverage; `130` means interrupted. Partial assessments still produce a report when possible. Header warnings are common and do not establish an exploitable vulnerability.

## Assessment behavior

- TLS verification is enabled. Proxy environment variables are ignored. There are no credentials, browser cookies, or authentication options. Server cookies are suppressed on subsequent requests.
- Scope is the exact scheme, hostname, and effective port of the target. CDN scripts and cross-origin redirects are skipped. HTTP-to-HTTPS redirects require starting with the HTTPS URL. This is a local CLI, not an SSRF-hardened service for accepting untrusted targets; DNS addresses are not pinned.
- At most six redirect-chain requests are made per fetch. Request failures and oversized responses become coverage errors. There are no retries or recursive crawling. Timeouts apply to individual HTTP phases, not the total assessment duration.
- HTML scripts and same-origin external scripts are analyzed. JavaScript is never executed. Literal quoted `/api`, `/rest`, and `/graphql` paths are discovered; dynamically assembled routes, source maps, imports and UUID objects are outside coverage.
- Header checks consider HTML context for CSP and framing protections. CORS checks concern the starting resource only, use a single synthetic Origin, and do not perform preflights. Wildcard public access is informational in many applications; reflected credentialed access needs sensitive-content validation.
- Secret detection is heuristic. Values are neither validated remotely nor written into findings. Query values are redacted in reports; URL paths and parameter names remain visible and may be sensitive. Protect the resulting report appropriately.
- BOLA review changes one numeric path component or ID-like query parameter by one. It flags distinct nonempty successful JSON responses available anonymously. Public records can trigger findings. Identical responses, redirects to a common destination, empty JSON and obvious JSON errors are excluded. This cannot confirm object ownership violations, and it cannot assess authenticated BOLA. Confirm manually using two authorized test accounts and known test objects.

## Source layout

- [main.py](main.py): argument validation, terminal status, orchestration and exit codes.
- [scanner.py](apisentry/core/scanner.py): bounded async transport and shared result models.
- [headers.py](apisentry/core/headers.py): security-header and CORS analysis.
- [js_parser.py](apisentry/core/js_parser.py): script discovery and redacted pattern findings.
- [bola_checker.py](apisentry/core/bola_checker.py): optional anonymous numeric-ID probes.
- [html_report.py](apisentry/reporters/html_report.py) and [report.html](templates/report.html): autoescaped, self-contained responsive HTML reporting without third-party assets.

## Validation

```powershell
python -m unittest discover -s tests -v
python -m compileall -q apisentry main.py
```

Tests use mock HTTP transports; they make no external requests. Assessments are deliberately limited heuristics, not a replacement for an authenticated application security review.
