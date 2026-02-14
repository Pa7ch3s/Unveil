"""
P2: Instrumentation hints per surface — "hook X", "run Frida script Y" to bridge static findings to dynamic testing.
"""
from typing import List, Dict, Any

# Per-surface hints: suggestion (plain language) and optional Frida/script one-liner or reference.
SURFACE_HINTS: Dict[str, List[Dict[str, str]]] = {
    "electron_preload": [
        {"suggestion": "Hook require('child_process') in renderer to confirm preload execution.", "frida_hint": "Frida: attach to Electron renderer; hook require or child_process.execSync."},
        {"suggestion": "Replace preload path with script that logs to file; confirm load order.", "frida_hint": "Override preload path via ELECTRON_RUN_AS_NODE or replace preload.js."},
    ],
    "preload_write": [
        {"suggestion": "Monitor file writes to app.asar or preload.js path (ProcMon/fs_usage).", "frida_hint": "Hook fs.writeFileSync in main process to detect preload writes."},
    ],
    "electron_helper": [
        {"suggestion": "Hook helper process spawn; inspect command line and IPC.", "frida_hint": "Frida: attach to helper binary; hook exec/spawn or IPC receive."},
    ],
    "network_mitm": [
        {"suggestion": "Set proxy and Burp CA; confirm TLS bypass or cert pinning bypass.", "frida_hint": "Frida: hook SSL_CTX_set_verify or NSURLSession to bypass cert validation."},
    ],
    "qt_rpath_plugin_drop": [
        {"suggestion": "Hook QLibrary/QLibrary::load or plugin loader to confirm plugin path.", "frida_hint": "Frida: hook dlopen or Qt plugin loading in app."},
    ],
    "macos_launch_persistence": [
        {"suggestion": "Monitor LaunchAgents/LaunchDaemons dir for new plist (fs_usage).", "frida_hint": "Hook launchctl submit or plist read to trace persistence."},
    ],
    "windows_persistence": [
        {"suggestion": "Monitor Registry Run key and Startup folder (ProcMon).", "frida_hint": "ProcMon: filter RegSetValue for Run keys; filter CreateFile for Startup."},
    ],
    "dotnet_managed": [
        {"suggestion": "Hook BinaryFormatter.Deserialize or Assembly.LoadFrom to confirm sink.", "frida_hint": "Frida/.NET: hook System.Runtime.Serialization or Assembly.Load*."},
    ],
    "linux_persistence": [
        {"suggestion": "Monitor systemd user dir and crontab (auditd or inotify).", "frida_hint": "Hook systemd/cron APIs or watch .service/crontab paths."},
    ],
    "jar_archive": [
        {"suggestion": "Hook ObjectInputStream.readObject or ClassLoader.defineClass.", "frida_hint": "Java agent or Frida: hook deserialization in JVM."},
    ],
}


def build_instrumentation_hints(chains: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    From attack-graph chains, build a flat list of instrumentation hints (one per surface per chain).
    Returns list of {"surface", "component_label", "suggestion", "frida_hint"}.
    """
    seen = set()
    out = []
    for entry in chains or []:
        surface = (entry.get("suggested_surface") or "").strip()
        if not surface or surface in seen:
            continue
        hints_list = SURFACE_HINTS.get(surface)
        if not hints_list:
            continue
        seen.add(surface)
        component = (entry.get("component_label") or entry.get("missing_role_label") or surface)
        for h in hints_list:
            out.append({
                "surface": surface,
                "component_label": component,
                "suggestion": h.get("suggestion") or "",
                "frida_hint": h.get("frida_hint") or "",
            })
    return out[:100]
