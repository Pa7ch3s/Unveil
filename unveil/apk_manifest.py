"""
P2: APK manifest summary for triage — permissions, debuggable, cleartext.
Uses aapt or aapt2 dump badging when available; otherwise returns minimal/empty.
"""
from pathlib import Path
import re
import subprocess
from typing import Dict, List, Any, Optional


# Permissions we consider dangerous or sensitive for pentest triage
DANGEROUS_OR_SENSITIVE = {
    "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "CAMERA", "RECORD_AUDIO",
    "READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
    "CALL_PHONE", "READ_PHONE_STATE", "BIND_", "RECEIVE_BOOT_COMPLETED",
    "FOREGROUND_SERVICE", "WAKE_LOCK", "VIBRATE", "BLUETOOTH", "NFC",
    "GET_ACCOUNTS", "USE_CREDENTIALS", "MANAGE_ACCOUNTS", "AUTHENTICATE_ACCOUNTS",
    "READ_LOGS", "WRITE_SECURE_SETTINGS", "INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
}


def _find_aapt() -> Optional[str]:
    """Return path to aapt or aapt2, or None."""
    for cmd in ("aapt", "aapt2"):
        try:
            r = subprocess.run(
                [cmd, "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode == 0 or cmd in (r.stdout or "") or cmd in (r.stderr or ""):
                return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        try:
            r = subprocess.run(
                [cmd, "dump", "badging", "--help"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode == 0:
                return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return None


def _run_badging(apk_path: str, aapt_cmd: str) -> str:
    try:
        r = subprocess.run(
            [aapt_cmd, "dump", "badging", apk_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode == 0:
            return r.stdout or ""
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ""


def get_apk_manifest_summary(apk_path: str) -> Dict[str, Any]:
    """
    Return a short manifest summary for triage: package, permissions (dangerous/sensitive),
    debuggable, usesCleartextTraffic. Uses aapt/aapt2 when available.
    """
    out = {
        "package": None,
        "version_code": None,
        "version_name": None,
        "permissions": [],
        "dangerous_or_sensitive_permissions": [],
        "debuggable": False,
        "uses_cleartext_traffic": None,
        "exported_components": [],
        "note": None,
    }
    path = Path(apk_path)
    if not path.is_file() or path.suffix.lower() != ".apk":
        out["note"] = "Not an APK path"
        return out

    aapt = _find_aapt()
    if not aapt:
        out["note"] = "aapt/aapt2 not found; install Android build-tools for full manifest summary"
        return out

    raw = _run_badging(apk_path, aapt)
    if not raw:
        out["note"] = "aapt dump badging produced no output"
        return out

    # package: name='com.example' versionCode='1' versionName='1.0'
    m = re.search(r"name='([^']+)'", raw)
    if m:
        out["package"] = m.group(1)
    m = re.search(r"versionCode='([^']*)'", raw)
    if m:
        out["version_code"] = m.group(1)
    m = re.search(r"versionName='([^']*)'", raw)
    if m:
        out["version_name"] = m.group(1)

    # uses-permission: name='android.permission.INTERNET'
    for m in re.finditer(r"uses-permission(?:-\w+)?:\s*name='([^']+)'", raw):
        perm = m.group(1)
        if perm.startswith("android.permission."):
            short = perm.replace("android.permission.", "")
        else:
            short = perm
        if short not in out["permissions"]:
            out["permissions"].append(short)
        for danger in DANGEROUS_OR_SENSITIVE:
            if danger in short or short in danger:
                if short not in out["dangerous_or_sensitive_permissions"]:
                    out["dangerous_or_sensitive_permissions"].append(short)
                break

    # application-debuggable
    out["debuggable"] = "application-debuggable:'true'" in raw or "application-debuggable: true" in raw

    # usesCleartextTraffic: aapt dump badging sometimes shows it; try grep
    out["uses_cleartext_traffic"] = "usesCleartextTraffic" in raw and ("true" in raw or "1" in raw)
    if "usesCleartextTraffic" not in raw:
        out["uses_cleartext_traffic"] = None  # unknown

    # Exported components: from badging we get launchable-activity; for full list need xmltree
    for m in re.finditer(r"launchable-activity:\s*name='([^']+)'", raw):
        name = m.group(1)
        if name and name not in out["exported_components"]:
            out["exported_components"].append(name)

    return out
