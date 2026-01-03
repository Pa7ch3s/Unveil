CLASS_INTEL = {
    "electron_asar_preload": {
        "vectors": ["asar_preload_overwrite", "preload_path_injection"],
        "chains": ["ANCHOR→BLADE"],
        "meaning": "persistent execution surface"
    },
    "electron_helper_ipc": {
        "vectors": ["ipc_method_abuse", "helper_spawn_hijack"],
        "chains": ["BRIDGE→BLADE"],
        "meaning": "lateral movement surface"
    },
    "ats_mitm_downgrade": {
        "vectors": ["tls_downgrade", "local_proxy_injection"],
        "chains": ["BRIDGE→BLADE"],
        "meaning": "traffic interception surface"
    }
}


def synthesize(surfaces):
    indicators = []

    for s in surfaces:
        name = s.get("surface")

        if name == "preload_write":
            indicators.append({
                "class": "electron_asar_preload",
                "impact": "ASAR preload RCE chain"
            })

        if name == "ipc_helper":
            indicators.append({
                "class": "electron_helper_ipc",
                "impact": "Helper IPC trust boundary escape"
            })

        if name == "network_mitm":
            indicators.append({
                "class": "ats_mitm_downgrade",
                "impact": "Local MITM + TLS downgrade"
            })

        if name == "electron_preload":
            indicators.append({
                "class": "electron_asar_preload",
                "impact": "Electron preload persistence"
            })

        if name == "electron_helper":
            indicators.append({
                "class": "electron_helper_ipc",
                "impact": "Electron helper lateral execution"
            })

    for i in indicators:
        i["intel"] = CLASS_INTEL.get(i["class"], {})

    return indicators
