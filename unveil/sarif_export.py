"""
Export Unveil report to SARIF 2.1 for CI (e.g. GitHub Code Scanning, VS Code SARIF viewer).
"""
import json as _json
from pathlib import Path


def report_to_sarif(report, run_uri=None):
    """
    Convert an Unveil report dict to SARIF 2.1 log.
    run_uri: optional logical URI for the scan (e.g. "file:///path/to/target").
    """
    target = (report.get("metadata") or {}).get("target", "")
    verdict = report.get("verdict") or {}
    band = verdict.get("exploitability_band", "UNKNOWN")
    findings = report.get("findings") or []
    results_sarif = []

    # Map band to SARIF level
    level = "warning"
    if band == "HIGH":
        level = "error"
    elif band == "LOW":
        level = "note"

    rule_id = "unveil/exploitability"
    results_sarif.append({
        "ruleId": rule_id,
        "level": level,
        "message": {"text": f"Exploitability band: {band}; target: {target}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": run_uri or target}}}],
    })

    for f in findings[:100]:
        cls = f.get("class", "")
        paths = f.get("surface", [])
        for p in (paths if isinstance(paths, list) else [paths])[:5]:
            results_sarif.append({
                "ruleId": "unveil/surface",
                "level": "warning",
                "message": {"text": f"Surface: {cls}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(p)}}}],
            })

    checklist = report.get("checklist_findings") or []
    for c in checklist[:80]:
        results_sarif.append({
            "ruleId": "unveil/checklist",
            "level": "warning",
            "message": {"text": c.get("snippet", "")[:200]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": c.get("file", "")}}}],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Unveil",
                        "version": "0.7.0",
                        "informationUri": "https://github.com/Pa7ch3s/Unveil",
                        "rules": [
                            {
                                "id": "unveil/exploitability",
                                "name": "Exploitability band",
                                "shortDescription": {"text": "Overall exploitability assessment"},
                            },
                            {
                                "id": "unveil/surface",
                                "name": "Attack surface",
                                "shortDescription": {"text": "Weaponizable surface finding"},
                            },
                            {
                                "id": "unveil/checklist",
                                "name": "Checklist / potential secret",
                                "shortDescription": {"text": "Static analysis checklist item or potential hardcoded credential"},
                            },
                        ],
                    }
                },
                "results": results_sarif,
            }
        ],
    }


def write_sarif(report, output_path):
    """Write report as SARIF JSON to output_path."""
    Path(output_path).write_text(
        _json.dumps(report_to_sarif(report), indent=2),
        encoding="utf-8",
    )
