from collections import defaultdict

REQUIRED_CHAIN = ["ANCHOR", "BRIDGE", "BLADE"]

def compile(synth_indicators, surfaces, context):
    roles = set()
    completion = 0.0
    hunt_queries = []
    cwe_map = set()
    families = set()

    for s in synth_indicators or []:
        intel = s.get("intel", {})
        role = intel.get("killchain_role")
        weight = intel.get("completion_weight", 0)

        if role:
            roles.add(role)
            completion += weight

        families.update(intel.get("families", []))
        cwe_map.update(intel.get("cwe_classes", []))

        for tag in intel.get("cve_search_tags", []):
            hunt_queries.append(tag)

    completion = min(completion, 1.0)

    missing = [r for r in REQUIRED_CHAIN if r not in roles]

    if completion >= 0.85:
        band = "CRITICAL"
    elif completion >= 0.6:
        band = "HIGH"
    elif completion >= 0.35:
        band = "MED"
    else:
        band = "LOW"

    return {
        "exploitability_band": band,
        "killchain_complete": completion >= 0.85,
        "chain_completion": round(completion, 2),
        "missing_roles": missing,
        "families": sorted(families),
        "cwe_classes": sorted(cwe_map),
        "hunt_queries": sorted(set(hunt_queries))
    }
