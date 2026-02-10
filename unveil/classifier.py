from pathlib import Path

def classify(entry):
    p = entry.get("file", "").lower()
    analysis = entry.get("analysis") or {}
    imports_list = analysis.get("imports") or []
    imports = (imports_list[0].get("imports", []) if imports_list else []) or []
    entropy = analysis.get("entropy", 0) or 0

    surfaces = []
    exploits = []

    # ---------- SURFACE GENERATORS ----------

    # Electron preload / runtime presence (BLADE candidate)
    # - direct preload.js
    # - or binaries that link against the Electron framework binary
    if p.endswith("preload.js"):
        surfaces.append("electron_preload")
        exploits.append("ELECTRON_PRELOAD_RCE")

    if any("Electron" in i for i in imports):
        surfaces.append("electron_preload")
        exploits.append("ELECTRON_PRELOAD_RCE")

    # Electron ASAR / preload config presence (ANCHOR candidate)
    # Heuristic: artifacts living under app.asar(.unpacked) paths
    if "app.asar" in p:
        exploits.append("electron_asar_preload")

    # Qt plugin rpath anchor (ANCHOR)
    # QtCore/QtGui/Qt5/Qt6 in imports, or qt.conf / plugin paths
    qt_import = any(
        "QtCore" in i or "QtGui" in i or "Qt5" in i or "Qt6" in i
        for i in imports
    )
    if qt_import:
        surfaces.append("qt_rpath_plugin_drop")
    if "qt.conf" in p:
        surfaces.append("qt_rpath_plugin_drop")
    if "plugins" in p and "qt" in p:
        surfaces.append("qt_rpath_plugin_drop")

    # Helper / IPC / crashpad bridge surface (BRIDGE)
    # Order: helpers (process names, Helper.app), then IPC, then crashpad
    if "helper" in p:
        surfaces.append("electron_helper")
    if "ipc" in p:
        surfaces.append("electron_helper")
    if "crashpad" in p:
        surfaces.append("electron_helper")

    # Relative rpath pivot anchor
    if any(i.startswith("@executable_path") for i in imports):
        surfaces.append("relative_rpath_pivot")

    # macOS persistence (ANCHOR) – LaunchAgents, LaunchDaemons, XPC, login items
    if "launchagents" in p or "launchdaemons" in p:
        surfaces.append("macos_launch_persistence")
    if "loginitems" in p or "login items" in p:
        surfaces.append("macos_launch_persistence")
    if ".xpc" in p or "xpcservice" in p or "xpc service" in p:
        surfaces.append("macos_launch_persistence")
    if p.endswith(".plist") and ("launch" in p or "daemon" in p):
        surfaces.append("macos_launch_persistence")

    # ---------- EXPLOIT ATTRIBUTES ----------

    if entropy > 6.9:
        exploits.append("PACKED_OR_PROTECTED")

    return {
        "surfaces": list(set(surfaces)),
        "exploits": list(set(exploits))
    }
