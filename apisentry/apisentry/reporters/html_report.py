"""Escaped HTML reporting with sensitive URL values suppressed."""

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from ..core.scanner import ScanResult


def safe_url(url: str) -> str:
    parts = urlsplit(url)
    query = urlencode([(key, "[redacted]") for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
    return urlunsplit(parts._replace(query=query, fragment=""))


def render_report(result: ScanResult, destination: Path) -> Path:
    # Repository layout keeps templates alongside the package.
    template_dir = Path(__file__).resolve().parents[2] / "templates"
    environment = Environment(loader=FileSystemLoader(template_dir),
                              autoescape=select_autoescape(["html"]), undefined=StrictUndefined)
    environment.filters["safe_url"] = safe_url
    html = environment.get_template("report.html").render(
        result=result, generated=datetime.now(timezone.utc).isoformat(),
        risks=("High", "Medium", "Low"))
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(html, encoding="utf-8")
    return destination
