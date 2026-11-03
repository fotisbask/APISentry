"""APISentry command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import math
from pathlib import Path

from rich.console import Console
from rich.table import Table

from apisentry import __version__
from apisentry.core.bola_checker import check_bola
from apisentry.core.headers import audit_headers
from apisentry.core.js_parser import discover_javascript
from apisentry.core.scanner import ScanResult, Scanner, normalize_url
from apisentry.reporters.html_report import render_report


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return parsed


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description="APISentry — authorized, same-origin web/API assessment")
    cli.add_argument("--version", action="version", version=__version__)
    cli.add_argument("--target", required=True, help="Absolute HTTP(S) URL in your authorized scope")
    cli.add_argument("--output", type=Path, default=Path("apisentry-report.html"))
    cli.add_argument("--timeout", type=positive_float, default=10.0)
    cli.add_argument("--concurrency", type=positive_int, default=4)
    cli.add_argument("--max-requests", type=positive_int, default=100)
    cli.add_argument("--max-bytes", type=positive_int, default=2_000_000)
    cli.add_argument("--delay", type=positive_float, default=0.1, help="Minimum seconds between request starts")
    cli.add_argument("--max-scripts", type=positive_int, default=20)
    cli.add_argument("--bola", action="store_true", help="Enable active anonymous adjacent-ID GET probes")
    cli.add_argument("--max-bola-checks", type=positive_int, default=10)
    return cli


async def assess(args: argparse.Namespace) -> ScanResult:
    result = ScanResult(normalize_url(args.target))
    async with Scanner(result.target, timeout=args.timeout, concurrency=args.concurrency,
                       max_requests=args.max_requests, max_bytes=args.max_bytes, delay=args.delay) as scanner:
        response = await scanner.fetch(result.target)
        if response is not None:
            result.findings.extend(audit_headers(response))
            if not response.is_success:
                scanner.errors.append(f"Target returned HTTP {response.status_code}; discovery skipped")
            else:
                result.endpoints, issues = await discover_javascript(response, scanner, args.max_scripts)
                result.findings.extend(issues)
                probe_origin = "https://apisentry-probe.invalid"
                cors = await scanner.fetch(str(response.url), headers={"Origin": probe_origin})
                if cors is not None:
                    result.findings.extend(audit_headers(cors, probe_origin))
                if args.bola:
                    result.findings.extend(await check_bola(result.endpoints, scanner, args.max_bola_checks))
        result.requests = scanner.requests
        result.errors = scanner.errors.copy()
    result.findings = list(dict.fromkeys(result.findings))
    return result


def main() -> int:
    cli = parser()
    args = cli.parse_args()
    console = Console()
    try:
        normalize_url(args.target)
        with console.status("Assessing same-origin resources…", spinner="dots"):
            result = asyncio.run(assess(args))
        report = render_report(result, args.output)
    except KeyboardInterrupt:
        console.print("Assessment interrupted.", style="yellow")
        return 130
    except (ValueError, OSError) as exc:
        console.print(f"Assessment failed: {type(exc).__name__}: {exc}", style="red", markup=False)
        return 2
    table = Table(title="APISentry findings")
    table.add_column("Risk")
    table.add_column("Count", justify="right")
    for risk, color in (("High", "red"), ("Medium", "yellow"), ("Low", "cyan")):
        table.add_row(risk, str(sum(f.risk == risk for f in result.findings)), style=color)
    console.print(table)
    console.print(f"Requests: {result.requests} | Coverage errors: {len(result.errors)}", markup=False)
    console.print(f"Report: {report}", markup=False)
    return 2 if result.errors else (1 if result.findings else 0)


if __name__ == "__main__":
    raise SystemExit(main())
