from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..engine import ScanResult

TEMPLATE_DIR = Path(__file__).parent / "templates"


def write_html_report(result: ScanResult, output_path: str) -> None:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report_template.html")

    html = template.render(
        account_id=result.account_id,
        regions_scanned=result.regions_scanned,
        services_scanned=result.services_scanned,
        duration_seconds=round(result.duration_seconds, 2),
        total_findings=len(result.findings),
        by_severity=result.summary_by_severity(),
        findings=[f.to_dict() for f in result.findings],
    )
    Path(output_path).write_text(html)
