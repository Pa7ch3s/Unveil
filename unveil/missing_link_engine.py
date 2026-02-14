# Plain-language labels for thick-client testing (ANCHOR/BRIDGE/BLADE).
# Shown in report and UI so non-experts understand what to do next.
ROLE_LABELS = {
    "ANCHOR": "Persistence / foothold",
    "BRIDGE": "Lateral movement",
    "BLADE": "Code execution",
}
ROLE_DESCRIPTIONS = {
    "ANCHOR": "Get a way to run again (e.g. on next launch) or influence what the app loads.",
    "BRIDGE": "Move from one process or privilege level to another (helpers, network, IPC).",
    "BLADE": "Execute attacker-controlled code inside the app (renderer, main process, etc.).",
}

# Human-readable names for the actual vulnerable component/surface (shown first in UI).
SURFACE_LABELS = {
    "electron_preload": "Electron preload.js",
    "preload_write": "Electron preload write / ASAR",
    "electron_asar_preload": "Electron ASAR / preload path",
    "electron_helper": "Electron helper process",
    "network_mitm": "Network / TLS (MITM)",
    "qt_rpath_plugin_drop": "Qt plugin dir / rpath",
    "macos_launch_persistence": "macOS LaunchAgent / XPC",
    "windows_persistence": "Windows Run / Services / Tasks",
    "dotnet_managed": ".NET managed / assembly load",
    "linux_persistence": "Linux systemd / cron / autostart",
    "jar_archive": "JAR / Java archive",
}

MISSING_LINK_TEMPLATES = {
    "ANCHOR": [
        {
            "surface": "qt_rpath_plugin_drop",
            "hunt": "qt.conf, @rpath plugin injection, writable plugin dirs",
            "reason": "required to persist execution"
        },
        {
            "surface": "electron_asar_preload",
            "hunt": "asar, preload.js, preload path overrides",
            "reason": "required to regain execution on relaunch"
        }
    ],
    "BRIDGE": [
        {
            "surface": "electron_helper",
            "hunt": "crashpad_handler, helper_process, IPC services",
            "reason": "required to move laterally into privileged helpers"
        },
        {
            "surface": "network_mitm",
            "hunt": "ATS exceptions, TLS downgrade paths",
            "reason": "required for network interception or injection"
        }
    ],
    "BLADE": [
        {
            "surface": "electron_preload",
            "hunt": "preload.js, renderer RCE, ASAR write, code execution vectors",
            "reason": "required for final code execution in renderer/main process"
        },
        {
            "surface": "preload_write",
            "hunt": "writable preload path, ASAR unpacked dir, electron main process",
            "reason": "required to inject code into Electron process"
        }
    ]
}

def infer_missing_links(missing_roles):
    out = []
    for r in missing_roles:
        for t in MISSING_LINK_TEMPLATES.get(r, []):
            out.append({
                "missing_role": r,
                "suggested_surface": t["surface"],
                "hunt_targets": t["hunt"],
                "reason": t["reason"]
            })
    return out


def enrich_hunt_plan_with_matched_paths(hunt_plan, discovered_assets, max_paths_per_entry=15):
    """
    Add matched_paths to each hunt_plan entry: actual paths from discovered_assets
    that match keywords in hunt_targets (e.g. preload.js -> paths containing 'preload.js').
    """
    if not hunt_plan or not discovered_assets:
        return hunt_plan
    all_paths = []
    for paths in discovered_assets.values():
        if isinstance(paths, list):
            all_paths.extend(p for p in paths if isinstance(p, str))
    if not all_paths:
        return hunt_plan
    out = []
    for entry in hunt_plan:
        e = dict(entry)
        hunt_str = (e.get("hunt_targets") or "").strip()
        if not hunt_str:
            out.append(e)
            continue
        keywords = [k.strip().lower() for k in hunt_str.replace(",", " ").split() if len(k.strip()) > 2]
        matched = []
        seen = set()
        for p in all_paths:
            if len(matched) >= max_paths_per_entry:
                break
            pl = p.lower()
            if pl in seen:
                continue
            for kw in keywords:
                if kw in pl:
                    matched.append(p)
                    seen.add(pl)
                    break
        e["matched_paths"] = matched[:max_paths_per_entry]
        out.append(e)
    return out
