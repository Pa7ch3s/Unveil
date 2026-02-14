"""
Permission audit for thick-client pen testing: identify writable dirs/files that could enable
DLL hijacking, config tampering, or persistence. Cross-platform (Windows icacls, macOS/Linux stat).
"""
from pathlib import Path
import os
import subprocess
import re


def _run(cmd, cwd=None):
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            cwd=cwd,
        )
        return (r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip())
    except Exception:
        return (-1, "", "")


def audit_path(path: str, max_depth: int = 0) -> list:
    """
    Audit a single path (file or dir) for permission findings.
    Returns list of {"path": str, "finding": str, "detail": str}.
    max_depth: for dirs, 0 = only the dir itself; 1 = dir + direct children (for key exe/dll).
    """
    path = Path(path).resolve()
    if not path.exists():
        return []
    out = []

    if os.name == "nt":
        # Windows: icacls path
        code, stdout, stderr = _run(["icacls", str(path)])
        if code != 0:
            return []
        # Look for (F) Full, (M) Modify, (W) Write, (WD) Write DAC, (WO) Write Owner, Everyone, Users
        line = (stdout + "\n" + stderr).split("\n")[0] if (stdout or stderr) else ""
        if "Everyone" in line and ("(F)" in line or "(M)" in line or "(W)" in line or "(C)" in line):
            out.append({
                "path": str(path),
                "finding": "Writable by Everyone",
                "detail": line[:200],
            })
        elif "Everyone" in line:
            out.append({
                "path": str(path),
                "finding": "Everyone has access",
                "detail": line[:200],
            })
        # Check for BUILTIN\Users with write
        if "Users" in line and ("(F)" in line or "(M)" in line or "(W)" in line):
            out.append({
                "path": str(path),
                "finding": "Writable by Users",
                "detail": line[:200],
            })
    else:
        # macOS / Linux: stat or ls -ld
        code, stdout, stderr = _run(["stat", "-c", "%a %U %G", str(path)])  # Linux
        if code != 0:
            code, stdout, stderr = _run(["stat", "-f", "%Lp %Su %Sg", str(path)])  # macOS
        if code == 0 and stdout:
            parts = stdout.split()
            if len(parts) >= 1:
                mode = parts[0]
                if len(mode) >= 3:
                    # world-writable (last digit 2 or 6 or 7)
                    world = mode[-1] if len(mode) == 3 else (mode[-3] if len(mode) >= 3 else "")
                    if world in ("2", "3", "6", "7"):
                        out.append({
                            "path": str(path),
                            "finding": "World-writable",
                            "detail": f"mode={mode}",
                        })
                    # group writable and not restricted
                    if len(mode) >= 2 and mode[-2] in ("2", "3", "6", "7"):
                        out.append({
                            "path": str(path),
                            "finding": "Group-writable",
                            "detail": f"mode={mode}",
                        })

    if max_depth > 0 and path.is_dir():
        try:
            for child in list(path.iterdir())[:50]:
                if child.is_file() and child.suffix.lower() in (".exe", ".dll", ".so", ".dylib", ".config", ".json"):
                    out.extend(audit_path(str(child), max_depth=0))
                if len(out) >= 20:
                    break
        except OSError:
            pass

    return out


def run_audit(target: str, include_parent_dir: bool = True) -> list:
    """
    Run permission audit on target path. If target is a file, also audit parent dir (install dir).
    Returns list of {"path", "finding", "detail"}.
    """
    p = Path(target).resolve()
    if not p.exists():
        return []
    paths_to_check = [str(p)]
    if include_parent_dir and p.is_file() and p.parent != p:
        paths_to_check.insert(0, str(p.parent))
    if p.is_dir():
        paths_to_check.append(str(p))
    seen_paths = set()
    results = []
    for path in paths_to_check:
        for item in audit_path(path, max_depth=0):
            key = (item["path"], item["finding"])
            if key not in seen_paths:
                seen_paths.add(key)
                results.append(item)
    return results[:100]
