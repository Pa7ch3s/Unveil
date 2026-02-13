"""
Electron version and hardening flags from package.json for CVE matching and report.
"""
from pathlib import Path
import json as _json


def get_electron_info(discovered_assets):
    """
    From discovered_assets["json"], find package.json and extract Electron version
    and hardening (nodeIntegration, contextIsolation, sandbox). Returns dict with
    version, nodeIntegration, contextIsolation, sandbox; or empty dict if not found.
    """
    out = {}
    paths = (discovered_assets or {}).get("json") or []
    pkg_path = None
    for p in paths:
        if Path(p).name.lower() == "package.json":
            pkg_path = p
            break
    if not pkg_path:
        return out
    try:
        data = _json.loads(Path(pkg_path).read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return out
    # Electron version: dependencies.electron or devDependencies.electron
    for key in ("dependencies", "devDependencies"):
        deps = data.get(key) or {}
        if isinstance(deps, dict) and "electron" in deps:
            ver = deps["electron"]
            if isinstance(ver, str) and ver.strip():
                out["version"] = ver.strip()
            break
    # Hardening: often in a nested config (electron-builder, electron main process config)
    # Common pattern: top-level or config.nodeIntegration, contextIsolation, sandbox
    def get_bool(obj, *keys):
        for k in keys:
            if isinstance(obj, dict) and k in obj:
                v = obj[k]
                if isinstance(v, bool):
                    return v
                if isinstance(v, str) and v.lower() in ("true", "1", "yes"):
                    return True
                if isinstance(v, str) and v.lower() in ("false", "0", "no"):
                    return False
            obj = obj.get(k) if isinstance(obj, dict) else None
        return None

    ni = get_bool(data, "nodeIntegration") or get_bool(data, "config", "nodeIntegration")
    ci = get_bool(data, "contextIsolation") or get_bool(data, "config", "contextIsolation")
    sb = get_bool(data, "sandbox") or get_bool(data, "config", "sandbox")
    if ni is not None:
        out["nodeIntegration"] = ni
    if ci is not None:
        out["contextIsolation"] = ci
    if sb is not None:
        out["sandbox"] = sb
    return out
