"""
Discovered assets by type for thick-client recon and chainability.
Aligns with OWASP thick-client testing: configs, manifests, scripts, certs, data.
"""
from pathlib import Path
import re
import json as _json

# Extension -> report type. Used for recon, chainability, and trust-boundary mapping.
ASSET_EXTENSIONS = {
    "html": {".html", ".htm"},
    "xml": {".xml"},
    "json": {".json"},
    "config": {".config", ".cfg", ".ini", ".yaml", ".yml"},
    "script": {".js", ".mjs", ".cjs", ".vbs", ".ps1", ".bat", ".cmd"},
    "plist": {".plist"},
    "manifest": {".manifest"},
    "policy": {".policy"},
    "cert": {".cer", ".crt", ".pem", ".pfx", ".der"},
    "data": {".db", ".sqlite", ".log"},
}

MAX_PER_TYPE = 500
REF_EXTRACT_MAX_SIZE = 512 * 1024  # 512KB cap for parsing
REF_EXTRACT_MAX_FILES = 100  # max files to parse per type for refs


def _suffix_to_type(suffix):
    suffix = (suffix or "").lower()
    for asset_type, exts in ASSET_EXTENSIONS.items():
        if suffix in exts:
            return asset_type
    return None


def collect_discovered_assets(root, out_dict, max_per_type=MAX_PER_TYPE):
    """Collect file paths by asset type under root. Fills out_dict[type] = [paths]."""
    root = Path(root)
    if not root.is_dir():
        return
    for item in root.rglob("*"):
        if not item.is_file():
            continue
        t = _suffix_to_type(item.suffix)
        if t is None:
            continue
        lst = out_dict.get(t)
        if lst is None:
            lst = []
            out_dict[t] = lst
        if len(lst) >= max_per_type:
            continue
        try:
            lst.append(str(item.resolve()))
        except (OSError, RuntimeError):
            pass


def _extract_refs_xml(path, content):
    """Extract path/URL-like refs from XML (href, path, src, file, key)."""
    refs = set()
    # Avoid full XML parse for huge files; use regex for common patterns
    for pattern in [
        r'[hH]ref\s*=\s*["\']([^"\']+)["\']',
        r'[pP]ath\s*=\s*["\']([^"\']+)["\']',
        r'[sS]rc\s*=\s*["\']([^"\']+)["\']',
        r'[fF]ile\s*=\s*["\']([^"\']+)["\']',
        r'[kK]ey\s*=\s*["\']([^"\']+)["\']',
        r'<[^>]+\s+[^=]*=\s*["\']([A-Za-z]:\\[^"\']+|[\/][^"\']+)["\']',
    ]:
        for m in re.finditer(pattern, content):
            refs.add(m.group(1).strip())
    return list(refs)[:50]  # cap refs per file


def _extract_refs_json(path, content):
    """Extract path/URL-like strings from JSON (values that look like paths or URLs)."""
    refs = set()
    try:
        data = _json.loads(content)
    except _json.JSONDecodeError:
        return []
    path_like = re.compile(r'^[A-Za-z]:\\|^\/|\.(dll|exe|so|dylib|js|json|config)$')
    url_like = re.compile(r'^https?://|^file://')

    def walk(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
        elif isinstance(obj, str) and len(obj) < 500:
            if path_like.search(obj) or url_like.search(obj) or "/" in obj or "\\" in obj:
                refs.add(obj.strip())
    walk(data)
    return list(refs)[:50]


def _extract_refs_config(path, content):
    """Extract paths from .config / .cfg (probing path, assembly, etc.)."""
    refs = set()
    for pattern in [
        r'[pP]robing\s+[pP]ath\s*=\s*["\']([^"\']+)["\']',
        r'[cC]odeBase\s*=\s*["\']([^"\']+)["\']',
        r'[pP]rivatePath\s*=\s*["\']([^"\']+)["\']',
        r'[pP]ath\s*=\s*["\']([^"\']+)["\']',
        r'[iI]nclude\s*=\s*["\']([^"\']+)["\']',
    ]:
        for m in re.finditer(pattern, content):
            refs.add(m.group(1).strip())
    return list(refs)[:50]


def extract_references(file_path, asset_type, max_size=REF_EXTRACT_MAX_SIZE):
    """
    Lightweight extraction of path/URL references from a config file.
    Returns {"file": path, "refs": [str, ...]} or None on error/skip.
    """
    path = Path(file_path)
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > max_size:
            return None
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return None
    refs = []
    if asset_type == "xml":
        refs = _extract_refs_xml(file_path, content)
    elif asset_type == "json":
        refs = _extract_refs_json(file_path, content)
    elif asset_type == "config":
        refs = _extract_refs_config(file_path, content)
    if not refs:
        return None
    return {"file": str(path.resolve()), "refs": refs}


def run_reference_extraction(discovered_assets, max_files_per_type=REF_EXTRACT_MAX_FILES):
    """
    Run reference extraction on xml, json, config assets. Returns list of
    {"file": path, "refs": [ref1, ...]} for chainability.
    """
    out = []
    for t in ("xml", "json", "config"):
        paths = discovered_assets.get(t) or []
        for p in paths[:max_files_per_type]:
            entry = extract_references(p, t)
            if entry:
                out.append(entry)
    return out
