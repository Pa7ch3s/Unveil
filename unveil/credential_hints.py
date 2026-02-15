"""
P2: Credential and storage hints — infer Keychain, CredMan, DPAPI, Electron safeStorage from imports/config.
Points testers to where to look (keychain dump, mimikatz, safeStorage decryption).
"""
import re
from pathlib import Path
from typing import Dict, List, Any


# Import/symbol patterns -> hint text and suggested next step
CREDENTIAL_PATTERNS = [
    # macOS Keychain
    (r"(?i)SecItem|Keychain|kSecClass|Security\.framework", "May use macOS Keychain", "Consider keychain dump (e.g. keychain-dumper, chainbreaker) or runtime inspection."),
    # Windows Credential Manager
    (r"(?i)CredRead|CredWrite|CredEnumerate|CredentialManager|advapi32.*Cred", "May use Windows Credential Manager", "Consider mimikatz or Windows Credential Manager export; check for stored credentials."),
    # DPAPI
    (r"(?i)CryptUnprotectData|CryptProtectData|DPAPI|DataProtection", "May use DPAPI for secrets", "Secrets may be DPAPI-protected; consider mimikatz dpapi:: or offline decryption with user context."),
    # Electron safeStorage
    (r"(?i)safeStorage|safe-storage|electron.*store|getPassword|setPassword", "May use Electron safeStorage", "Consider safeStorage decryption (e.g. electron-safe-storage-decrypt, or Frida hook on safeStorage)."),
    # Generic credential / token
    (r"(?i)Credential|Credentials|OAuth|Bearer|Token|getpass|keyring", "Credential/token handling present", "Look for hardcoded tokens or credential storage; check config and env."),
]


def _collect_imports_from_results(results: List[Dict]) -> List[tuple]:
    """Yield (file_path, import_symbol) for each result that has analysis.imports."""
    for r in results or []:
        path = r.get("file") or ""
        analysis = r.get("analysis") or {}
        imports_list = analysis.get("imports") or []
        for imp_group in imports_list:
            symbols = (imp_group.get("imports") or []) if isinstance(imp_group, dict) else []
            for sym in symbols:
                if isinstance(sym, str) and sym.strip():
                    yield (path, sym)


def build_credential_hints(results: List[Dict], discovered_assets: Dict[str, List] = None) -> List[Dict[str, Any]]:
    """
    Build credential/storage hints from binary imports and optional config/plist content.
    Returns list of { "hint", "path", "suggestion", "source" }.
    """
    out: List[Dict[str, Any]] = []
    seen: set = set()

    for path, symbol in _collect_imports_from_results(results):
        for pattern, hint, suggestion in CREDENTIAL_PATTERNS:
            if re.search(pattern, symbol):
                key = (hint, path)
                if key not in seen:
                    seen.add(key)
                    out.append({
                        "hint": hint,
                        "path": path,
                        "suggestion": suggestion,
                        "source": "imports",
                    })
                break

    # Optional: scan config/plist content for keychain/credential keywords (lightweight)
    if discovered_assets:
        config_paths = (discovered_assets.get("config") or [])[:20]
        plist_paths = (discovered_assets.get("plist") or [])[:20]
        for fpath in config_paths + plist_paths:
            try:
                content = Path(fpath).read_text(errors="ignore")[:8192]
            except Exception:
                continue
            for pattern, hint, suggestion in CREDENTIAL_PATTERNS:
                if re.search(pattern, content):
                    key = (hint, fpath)
                    if key not in seen:
                        seen.add(key)
                        out.append({
                            "hint": hint,
                            "path": fpath,
                            "suggestion": suggestion,
                            "source": "config",
                        })
                    break

    return out
