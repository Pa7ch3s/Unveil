from pathlib import Path

def classify(entry):
    p = entry.get("file", "").lower()
    imports = entry["analysis"]["imports"][0]["imports"]
    entropy = entry["analysis"].get("entropy", 0)

    surfaces = []
    exploits = []

    # ---------- SURFACE GENERATORS ----------

    # Electron preload surface (BLADE)
    if p.endswith("preload.js"):
        surfaces.append("electron_preload")
        exploits.append("ELECTRON_PRELOAD_RCE")

    if any("@rpath/Electron" in i for i in imports):
        surfaces.append("electron_preload")
        exploits.append("ELECTRON_PRELOAD_RCE")

    # Qt plugin rpath anchor (ANCHOR)
    if any("QtCore.framework" in i for i in imports):
        surfaces.append("qt_rpath_plugin_drop")

    # Helper / crash bridge surface (BRIDGE)
    if "crashpad" in p or "helper" in p:
        surfaces.append("electron_helper")

    # Relative rpath pivot anchor
    if any(i.startswith("@executable_path") for i in imports):
        surfaces.append("relative_rpath_pivot")

    # ---------- EXPLOIT ATTRIBUTES ----------

    if entropy > 6.9:
        exploits.append("PACKED_OR_PROTECTED")

    return {
        "surfaces": list(set(surfaces)),
        "exploits": list(set(exploits))
    }
