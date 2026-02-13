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
