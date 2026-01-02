#cat > unveil/core/verdict_compiler.py << 'EOF'
def compile(indicators, surfaces, fingerprint):
    verdict = {
        "exploitability_band": "LOW",
        "killchain_complete": False,
        "persistence_depth": 0,
        "lateral_adjacency": False,
        "reentry_survivable": False,
    }

    if not indicators:
        return verdict

    classes = {i["class"] for i in indicators}

    if "electron_asar_preload" in classes:
        verdict["persistence_depth"] += 2
        verdict["reentry_survivable"] = True

    if "electron_helper_ipc" in classes:
        verdict["lateral_adjacency"] = True
        verdict["persistence_depth"] += 1

    if "ats_mitm_downgrade" in classes:
        verdict["killchain_complete"] = True

    if verdict["persistence_depth"] >= 3 and verdict["killchain_complete"]:
        verdict["exploitability_band"] = "CRITICAL"
    elif verdict["persistence_depth"] >= 2:
        verdict["exploitability_band"] = "HIGH"
    elif verdict["persistence_depth"] >= 1:
        verdict["exploitability_band"] = "MEDIUM"

    return verdict
