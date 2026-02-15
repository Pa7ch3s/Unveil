"""
P0: Unified findings table for client reports.
Builds one row per finding (checklist + thick_client + high-value chains) with report severity,
evidence path/snippet, CWE, and recommendation. Export to CSV or Markdown table.
"""
import csv
from typing import List, Dict, Any, Optional

# Map internal severity to report severity (Critical/High/Medium/Low/Info)
SEVERITY_TO_REPORT = {
    "credential": "High",
    "dangerous_config": "Medium",
    "informational": "Low",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def _report_severity(severity: str) -> str:
    s = (severity or "").strip().lower()
    return SEVERITY_TO_REPORT.get(s) or "Info"


def _row(
    title: str,
    severity: str,
    category: str,
    path: str,
    snippet: str,
    cwe: str,
    recommendation: str,
    source: str = "",
) -> Dict[str, str]:
    return {
        "Title": title or "",
        "Severity": _report_severity(severity),
        "Category": category or "",
        "Path": path or "",
        "Snippet": (snippet or "")[:500],
        "CWE": cwe or "",
        "Recommendation": (recommendation or "")[:500],
        "Source": source or "",
    }


def build_findings_table(report: dict, max_rows: int = 200) -> List[Dict[str, str]]:
    """
    Build unified findings table from checklist_findings, thick_client_findings, and chains with matched_paths.
    Each row: Title, Severity, Category, Path, Snippet, CWE, Recommendation, Source.
    """
    out: List[Dict[str, str]] = []
    seen_key = set()

    def add(r: Dict[str, str]):
        key = (
            (r.get("Title") or "")[:200],
            (r.get("Path") or "")[:200],
            (r.get("Snippet") or "")[:200],
        )
        if key in seen_key:
            return
        seen_key.add(key)
        if len(out) < max_rows:
            out.append(r)

    verdict = report.get("verdict") or {}
    exploitability_band = verdict.get("exploitability_band") or ""

    # ---- Checklist findings
    for c in (report.get("checklist_findings") or [])[:80]:
        if not isinstance(c, dict):
            continue
        path = c.get("file") or ""
        pattern = c.get("pattern") or "Finding"
        snippet = c.get("snippet") or c.get("context") or ""
        severity = c.get("severity") or "informational"
        add(_row(
            title=f"Checklist: {pattern}",
            severity=severity,
            category="Checklist",
            path=path,
            snippet=snippet,
            cwe="",
            recommendation="Verify in config; remove or restrict if in production.",
            source="checklist",
        ))

    # ---- Thick-client findings (already have category, severity, hunt_suggestion)
    for t in (report.get("thick_client_findings") or [])[:60]:
        if not isinstance(t, dict):
            continue
        title = t.get("title") or "Thick client finding"
        category = t.get("category") or "Other"
        severity = t.get("severity") or "info"
        artifacts = t.get("artifacts") or []
        path = artifacts[0] if artifacts else ""
        if not isinstance(path, str):
            path = str(path) if path is not None else ""
        snippet = (t.get("summary") or "")[:400]
        rec = t.get("hunt_suggestion") or ""
        add(_row(
            title=title,
            severity=severity,
            category=category,
            path=path,
            snippet=snippet,
            cwe="",
            recommendation=rec,
            source="thick_client",
        ))

    # ---- Chains with matched_paths (high value)
    chains = (report.get("attack_graph") or {}).get("chains") or []
    for ch in chains:
        matched = ch.get("matched_paths") or []
        if not matched:
            continue
        role = ch.get("missing_role_label") or ch.get("missing_role") or ""
        surface = ch.get("component_label") or ch.get("suggested_surface") or ""
        path = matched[0] if matched else ""
        add(_row(
            title=f"Chain: {role} — {surface}",
            severity="High",
            category="Attack graph",
            path=path,
            snippet=f"{len(matched)} path(s) matched. Hunt: {ch.get('hunt_targets') or ''}"[:400],
            cwe="",
            recommendation=ch.get("reason") or "Test this surface first; use suggested payloads.",
            source="attack_graph",
        ))

    # Sort by severity order (Critical > High > Medium > Low > Info)
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    out.sort(key=lambda r: (order.get(r.get("Severity") or "Info", 5), r.get("Title") or ""))

    return out


def export_findings_csv(rows: List[Dict[str, str]], path: str) -> None:
    """Write findings table to CSV."""
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def export_findings_md(rows: List[Dict[str, str]]) -> str:
    """Return findings table as Markdown."""
    if not rows:
        return ""
    lines = ["| Title | Severity | Category | Path | Snippet | CWE | Recommendation |", "|-------|----------|----------|------|---------|-----|-----------------|"]
    for r in rows:
        title = (r.get("Title") or "").replace("|", "\\|")[:60]
        sev = r.get("Severity") or ""
        cat = (r.get("Category") or "").replace("|", "\\|")[:20]
        path = (r.get("Path") or "").replace("|", "\\|")[:50]
        snippet = (r.get("Snippet") or "").replace("|", "\\|").replace("\n", " ")[:80]
        cwe = r.get("CWE") or ""
        rec = (r.get("Recommendation") or "").replace("|", "\\|").replace("\n", " ")[:80]
        lines.append(f"| {title} | {sev} | {cat} | {path} | {snippet} | {cwe} | {rec} |")
    return "\n".join(lines)
