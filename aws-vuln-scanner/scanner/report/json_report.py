from __future__ import annotations

import json
from pathlib import Path

from ..engine import ScanResult


def write_json_report(result: ScanResult, output_path: str) -> None:
    payload = {
        "account_id": result.account_id,
        "regions_scanned": result.regions_scanned,
        "services_scanned": result.services_scanned,
        "duration_seconds": round(result.duration_seconds, 2),
        "summary": {
            "total_findings": len(result.findings),
            "by_severity": result.summary_by_severity(),
            "by_service": result.summary_by_service(),
        },
        "findings": [f.to_dict() for f in result.findings],
    }
    Path(output_path).write_text(json.dumps(payload, indent=2, default=str))
