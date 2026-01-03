from pathlib import Path

def classify(entry):
    p = entry.get("file","").lower()

    # --- Upgrade 2 blade recognition ---
    if p.endswith("preload.js"):
        return "ELECTRON_PRELOAD_RCE"

    imports = entry["analysis"]["imports"][0]["imports"]
    tags = []

    if any("@rpath/Electron" in i for i in imports):
        tags.append("ELECTRON_PRELOAD_RCE")

    if any("QtCore.framework" in i for i in imports):
        tags.append("QT_PLUGIN_RPATH_HIJACK")

    if "crashpad" in p or "helper" in p:
        tags.append("HELPER_BRIDGE")

    if any(i.startswith("@executable_path") for i in imports):
        tags.append("RELATIVE_RPATH_PIVOT")

    if entry["analysis"]["entropy"] > 6.9:
        tags.append("PACKED_OR_PROTECTED")

    return ",".join(tags) if tags else "NATIVE"
