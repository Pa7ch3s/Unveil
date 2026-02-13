"""
Diff and baseline: compare two Unveil reports for regression; suppress findings using a baseline.
"""
from pathlib import Path


def _finding_key(f):
    """Stable key for a finding for comparison."""
    cls = f.get("class", "")
    paths = f.get("surface", [])
    if not isinstance(paths, list):
        paths = [paths] if paths else []
    return (cls, tuple(sorted(str(p) for p in paths)))


def diff_reports(baseline_report, current_report):
    """
    Compare baseline_report and current_report. Returns dict:
      added_findings: list of findings in current not in baseline
      removed_findings: list of findings in baseline not in current
      verdict_changed: bool (exploitability_band or chain_completion changed)
    """
    base_findings = (baseline_report or {}).get("findings") or []
    cur_findings = (current_report or {}).get("findings") or []
    base_keys = set(_finding_key(f) for f in base_findings)
    cur_keys = set(_finding_key(f) for f in cur_findings)
    added = [f for f in cur_findings if _finding_key(f) not in base_keys]
    removed = [f for f in base_findings if _finding_key(f) not in cur_keys]
    v_base = (baseline_report or {}).get("verdict") or {}
    v_cur = (current_report or {}).get("verdict") or {}
    verdict_changed = (
        v_base.get("exploitability_band") != v_cur.get("exploitability_band")
        or v_base.get("chain_completion") != v_cur.get("chain_completion")
    )
    return {
        "added_findings": added,
        "removed_findings": removed,
        "verdict_changed": verdict_changed,
    }


def apply_baseline(current_report, baseline_report):
    """
    Return a copy of current_report with findings that appear in baseline_report
    marked (baseline_suppressed=True) and a top-level "diff" from diff_reports().
    """
    diff = diff_reports(baseline_report, current_report)
    baseline_keys = set(_finding_key(f) for f in ((baseline_report or {}).get("findings") or []))
    out = dict(current_report)
    out["findings"] = []
    for f in (current_report or {}).get("findings") or []:
        f = dict(f)
        f["baseline_suppressed"] = _finding_key(f) in baseline_keys
        out["findings"].append(f)
    out["diff"] = diff
    return out
