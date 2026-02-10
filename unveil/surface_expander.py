def expand(indicators, enum):
    out = []

    for i in indicators:
        c = i["class"]

        if c == "electron_asar_preload":
            path = i.get("file")
            if path:
                out.append({
                    "surface": "preload_write",
                    "path": path,
                    "trust_boundary": "renderer→main",
                    "reentry": "preload.js",
                    "impact": "persistent_rce"
                })

        if c == "electron_helper_ipc":
            helpers = enum.get("helpers") or []
            path = i.get("file")
            if path or helpers:
                out.append({
                    "surface": "ipc_helper",
                    "path": path or (helpers[0] if helpers else None),
                    "trust_boundary": "renderer→helper",
                    "reentry": "helper_relaunch",
                    "impact": "local_priv_esc"
                })

        if c == "ats_mitm_downgrade":
            out.append({
                "surface": "network_mitm",
                "domains": list(enum.get("ATS", {}).get("NSExceptionDomains", {}).keys()),
                "trust_boundary": "local_network",
                "reentry": "config_override",
                "impact": "traffic_injection"
            })

        if c == "QT_PLUGIN_RPATH_HIJACK":
            path = i.get("file")
            if path:
                out.append({
                    "surface": "qt_rpath_plugin_drop",
                    "path": path,
                    "trust_boundary": "plugin_loader",
                    "reentry": "qt.conf",
                    "impact": "persistent_code_execution"
                })

        if c == "ELECTRON_PRELOAD_RCE":
            out.append({
                "surface": "electron_preload",
                "path": i.get("file"),
                "trust_boundary": "renderer→main",
                "reentry": "preload.js",
                "impact": "persistent_rce"
            })

        if c == "HELPER_BRIDGE":
            out.append({
                "surface": "electron_helper",
                "path": i.get("file"),
                "trust_boundary": "renderer→helper",
                "reentry": "helper_process",
                "impact": "lateral_execution"
            })

        if c == "MACOS_LAUNCH_PERSISTENCE":
            path = i.get("file")
            if path:
                out.append({
                    "surface": "macos_launch_persistence",
                    "path": path,
                    "trust_boundary": "launchd",
                    "reentry": "plist_or_xpc",
                    "impact": "persistent_code_execution"
                })

    return out
