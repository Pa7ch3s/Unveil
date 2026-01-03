def synthesize(surfaces):
    rules = {
        "preload_write": {
            "class": "electron_asar_preload",
            "impact": "ASAR preload RCE chain",
            "intel": {
                "vectors": ["asar_preload_overwrite", "preload_path_injection"],
                "chains": ["ANCHOR→BLADE"],
                "meaning": "persistent execution surface",
            },
        },
        "electron_preload": {
            "class": "electron_asar_preload",
            "impact": "Electron preload persistence",
            "intel": {
                "vectors": ["asar_preload_overwrite", "preload_path_injection"],
                "chains": ["ANCHOR→BLADE"],
                "meaning": "persistent execution surface",
            },
        },
        "ipc_helper": {
            "class": "electron_helper_ipc",
            "impact": "Helper IPC trust boundary escape",
            "intel": {
                "vectors": ["ipc_method_abuse", "helper_spawn_hijack"],
                "chains": ["BRIDGE→BLADE"],
                "meaning": "lateral movement surface",
            },
        },
        "electron_helper": {
            "class": "electron_helper_ipc",
            "impact": "Electron helper lateral execution",
            "intel": {
                "vectors": ["ipc_method_abuse", "helper_spawn_hijack"],
                "chains": ["BRIDGE→BLADE"],
                "meaning": "lateral movement surface",
            },
        },
        "network_mitm": {
            "class": "ats_mitm_downgrade",
            "impact": "Local MITM + TLS downgrade",
            "intel": {
                "vectors": ["tls_downgrade", "ats_exception_abuse"],
                "chains": ["BLADE→BRIDGE"],
                "meaning": "network interception surface",
            },
        },
    }

    by_class = {}

    for s in surfaces or []:
        name = s.get("surface")
        rule = rules.get(name)
        if not rule:
            continue

        k = rule["class"]
        cur = by_class.get(k)
        if not cur:
            by_class[k] = {
                "class": rule["class"],
                "impact": rule["impact"],
                "intel": {
                    "vectors": [],
                    "chains": [],
                    "meaning": rule.get("intel", {}).get("meaning"),
                },
            }
            cur = by_class[k]

        cur["impact"] = cur.get("impact") or rule.get("impact")

        intel = rule.get("intel") or {}
        v = set(cur["intel"].get("vectors") or [])
        c = set(cur["intel"].get("chains") or [])
        v.update(intel.get("vectors") or [])
        c.update(intel.get("chains") or [])
        cur["intel"]["vectors"] = sorted(v)
        cur["intel"]["chains"] = sorted(c)

        if not cur["intel"].get("meaning"):
            cur["intel"]["meaning"] = intel.get("meaning")

    out = list(by_class.values())
    out.sort(key=lambda x: x.get("class", ""))
    return out
