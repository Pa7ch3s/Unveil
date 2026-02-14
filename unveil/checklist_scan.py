"""
Static analysis checklist: scan discovered config/json/env/script/plist/xml for common no-nos
(hardcoded credentials, secrets, and static analysis checklist items).
P2: severity per pattern; optional custom patterns from UNVEIL_CHECKLIST_EXTRA (JSON file).
"""
from pathlib import Path
import re
import os
import json
from typing import List, Tuple

CHECKLIST_MAX_FILE_SIZE = 512 * 1024  # 512KB (was 256KB) to catch larger configs
CHECKLIST_MAX_FILES_PER_TYPE = 80
CHECKLIST_MAX_FINDINGS_PER_FILE = 20
SNIPPET_LEN = 120

# Severity: credential (high), dangerous_config (medium), informational (low)
SEVERITY_CREDENTIAL = "credential"
SEVERITY_DANGEROUS = "dangerous_config"
SEVERITY_INFO = "informational"

# (pattern_name, regex, severity)
CHECKLIST_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("password_plain", re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^'\"\s]{4,})", re.IGNORECASE), SEVERITY_CREDENTIAL),
    ("api_key", re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([^'\"\s]{8,})", re.IGNORECASE), SEVERITY_CREDENTIAL),
    ("secret", re.compile(r"(?i)(?:secret|token|auth)\s*[=:]\s*['\"]?([^'\"\s]{8,})", re.IGNORECASE), SEVERITY_CREDENTIAL),
    ("aws_key", re.compile(r"(?i)(?:aws_?access_?key|aws_secret)\s*[=:]\s*['\"]?([^'\"\s]{10,})", re.IGNORECASE), SEVERITY_CREDENTIAL),
    ("connection_string", re.compile(r"(?i)(?:connectionstring|connection_?string|database_?url)\s*[=:]\s*['\"]?([^'\"]{10,})", re.IGNORECASE), SEVERITY_CREDENTIAL),
    ("private_key_path", re.compile(r"(?i)(?:private[_-]?key|keyfile|pem)\s*[=:]\s*['\"]?([^'\"\s]+)", re.IGNORECASE), SEVERITY_CREDENTIAL),
    ("bearer_token", re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})", re.IGNORECASE), SEVERITY_CREDENTIAL),
    ("basic_auth", re.compile(r"(?i)basic\s+([a-zA-Z0-9+/=]{20,})", re.IGNORECASE), SEVERITY_CREDENTIAL),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), SEVERITY_CREDENTIAL),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), SEVERITY_CREDENTIAL),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36,}|gho_[A-Za-z0-9]{36,}"), SEVERITY_CREDENTIAL),
    ("pem_private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), SEVERITY_CREDENTIAL),
    ("generic_key_long", re.compile(r"(?i)(?:key|credential)\s*[=:]\s*['\"]?([^'\"\s]{24,})", re.IGNORECASE), SEVERITY_CREDENTIAL),
    ("debug_true", re.compile(r"(?i)(?:debug|verbose)\s*[=:]\s*(?:true|1|yes)"), SEVERITY_DANGEROUS),
    ("disabled_ssl", re.compile(r"(?i)(?:rejectUnauthorized|strictSSL|verify)\s*[=:]\s*(?:false|0)"), SEVERITY_DANGEROUS),
    ("eval_or_danger", re.compile(r"(?i)(?:eval\s*\(|new\s+Function\s*\(|document\.write\s*\(|innerHTML\s*=)"), SEVERITY_DANGEROUS),
]


def _load_extra_patterns() -> List[Tuple[str, re.Pattern, str]]:
    """Load custom patterns from JSON file path in UNVEIL_CHECKLIST_EXTRA. Format: [{"pattern_name": "...", "regex": "...", "severity": "credential"|"dangerous_config"|"informational"}]."""
    extra = []
    path = os.environ.get("UNVEIL_CHECKLIST_EXTRA", "").strip()
    if not path:
        return extra
    try:
        p = Path(path)
        if not p.is_file():
            return extra
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return extra
        for item in data:
            if not isinstance(item, dict):
                continue
            name = (item.get("pattern_name") or item.get("name") or "").strip()
            regex_str = (item.get("regex") or "").strip()
            sev = (item.get("severity") or SEVERITY_INFO).strip().lower()
            if sev not in (SEVERITY_CREDENTIAL, SEVERITY_DANGEROUS, SEVERITY_INFO):
                sev = SEVERITY_INFO
            if name and regex_str:
                try:
                    extra.append((name, re.compile(regex_str), sev))
                except re.error:
                    pass
    except Exception:
        pass
    return extra


def _all_patterns() -> List[Tuple[str, re.Pattern, str]]:
    return CHECKLIST_PATTERNS + _load_extra_patterns()


def _snippet(line: str, start: int) -> str:
    """Return a short snippet around the match, sanitized for report."""
    s = line[max(0, start - 20) : start + SNIPPET_LEN].strip()
    s = s.replace("\n", " ").replace("\r", "")
    return s[:SNIPPET_LEN] + ("…" if len(s) > SNIPPET_LEN else "")


def scan_file(file_path: str, asset_type: str) -> List[dict]:
    """
    Scan one file for checklist patterns. Returns list of
    {"file": path, "pattern": name, "snippet": str, "line": int, "severity": str}.
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
    for name, pattern, severity in _all_patterns():
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
                    "severity": severity,
                })
    return findings


def run_checklist(discovered_assets: dict, max_per_type: int = CHECKLIST_MAX_FILES_PER_TYPE) -> List[dict]:
    """
    Run checklist scan on config, json, env, script, plist, and xml assets.
    Returns list of {"file", "pattern", "snippet", "line", "severity"} for report checklist_findings.
    """
    out = []
    for asset_type in ("config", "json", "env", "script", "plist", "xml"):
        paths = (discovered_assets or {}).get(asset_type) or []
        for path in paths[:max_per_type]:
            out.extend(scan_file(path, asset_type))
    return out[:500]  # cap total for report size
