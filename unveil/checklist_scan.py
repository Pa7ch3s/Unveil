"""
Static analysis checklist: scan discovered config/json/env/script for common no-nos
(hardcoded credentials, secrets, and static analysis checklist items).
"""
from pathlib import Path
import re
from typing import List

CHECKLIST_MAX_FILE_SIZE = 256 * 1024  # 256KB
CHECKLIST_MAX_FILES_PER_TYPE = 80
CHECKLIST_MAX_FINDINGS_PER_FILE = 20
SNIPPET_LEN = 120

# (pattern_name, regex) — keys/values that often indicate secrets or checklist items.
# Keep patterns specific to avoid massive false positives.
CHECKLIST_PATTERNS = [
    ("password_plain", re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^'\"\s]{4,})", re.IGNORECASE)),
    ("api_key", re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([^'\"\s]{8,})", re.IGNORECASE)),
    ("secret", re.compile(r"(?i)(?:secret|token|auth)\s*[=:]\s*['\"]?([^'\"\s]{8,})", re.IGNORECASE)),
    ("aws_key", re.compile(r"(?i)(?:aws_?access_?key|aws_secret)\s*[=:]\s*['\"]?([^'\"\s]{10,})", re.IGNORECASE)),
    ("connection_string", re.compile(r"(?i)(?:connectionstring|connection_?string|database_?url)\s*[=:]\s*['\"]?([^'\"]{10,})", re.IGNORECASE)),
    ("private_key_path", re.compile(r"(?i)(?:private[_-]?key|keyfile|pem)\s*[=:]\s*['\"]?([^'\"\s]+)", re.IGNORECASE)),
    ("bearer_token", re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})", re.IGNORECASE)),
    ("basic_auth", re.compile(r"(?i)basic\s+([a-zA-Z0-9+/=]{20,})", re.IGNORECASE)),
    ("debug_true", re.compile(r"(?i)(?:debug|verbose)\s*[=:]\s*(?:true|1|yes)")),
    ("disabled_ssl", re.compile(r"(?i)(?:rejectUnauthorized|strictSSL|verify)\s*[=:]\s*(?:false|0)")),
    ("eval_or_danger", re.compile(r"(?i)(?:eval\s*\(|new\s+Function\s*\(|document\.write\s*\(|innerHTML\s*=)")),
]


def _snippet(line: str, start: int) -> str:
    """Return a short snippet around the match, sanitized for report."""
    s = line[max(0, start - 20) : start + SNIPPET_LEN].strip()
    s = s.replace("\n", " ").replace("\r", "")
    return s[:SNIPPET_LEN] + ("…" if len(s) > SNIPPET_LEN else "")


def scan_file(file_path: str, asset_type: str) -> List[dict]:
    """
    Scan one file for checklist patterns. Returns list of
    {"file": path, "pattern": name, "snippet": str}.
    """
    path = Path(file_path)
    if not path.is_file():
        return []
    try:
        if path.stat().st_size > CHECKLIST_MAX_FILE_SIZE:
            return []
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    findings = []
    lines = content.splitlines()
    for name, pattern in CHECKLIST_PATTERNS:
        for i, line in enumerate(lines):
            if len(findings) >= CHECKLIST_MAX_FINDINGS_PER_FILE:
                return findings
            m = pattern.search(line)
            if m:
                snippet = _snippet(line, m.start())
                findings.append({
                    "file": file_path,
                    "pattern": name,
                    "snippet": snippet,
                    "line": i + 1,
                })
    return findings


def run_checklist(discovered_assets: dict, max_per_type: int = CHECKLIST_MAX_FILES_PER_TYPE) -> List[dict]:
    """
    Run checklist scan on config, json, env, and script assets.
    Returns list of {"file", "pattern", "snippet", "line"} for report checklist_findings.
    """
    out = []
    for asset_type in ("config", "json", "env", "script"):
        paths = (discovered_assets or {}).get(asset_type) or []
        for path in paths[:max_per_type]:
            out.extend(scan_file(path, asset_type))
    return out[:500]  # cap total for report size
