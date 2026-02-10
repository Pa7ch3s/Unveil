ANCHOR_HINTS = {
    "qt_rpath_plugin_drop": 0.45,
    "relative_rpath_pivot": 0.35,
    "writable_plugin_dir": 0.40,
}

BRIDGE_HINTS = {
    "electron_helper": 0.40,
    "ipc_helper": 0.35,
    "helper_spawn": 0.30,
    "network_mitm": 0.25,
}

def detect_candidates(findings):
    anchors = []
    bridges = []

    for f in findings:
        cls = f.get("class","")
        score = 0.0

        if cls in ANCHOR_HINTS:
            score = ANCHOR_HINTS[cls]
            anchors.append({
                "class": cls,
                "confidence": round(score,2),
                "paths": f.get("surface",[])
            })

        if cls in BRIDGE_HINTS:
            score = BRIDGE_HINTS[cls]
            bridges.append({
                "class": cls,
                "confidence": round(score,2),
                "paths": f.get("surface",[])
            })

    return anchors, bridges
