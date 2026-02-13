from unveil.chain_closure import detect_candidates
from unveil.missing_link_engine import infer_missing_links

ROLE_ORDER = ["ANCHOR","BRIDGE","BLADE"]

ROLE_WEIGHTS = {
    "ANCHOR": 0.35,
    "BRIDGE": 0.30,
    "BLADE": 0.35
}

def compile(synth, surfaces, findings, offensive=True):
    roles = {}
    families = set()
    cwe = set()
    hunt = set()
    score = 0.0

    for s in synth:
        intel = s.get("intel", {})
        r = intel.get("killchain_role")
        if not r:
            continue

        roles[r] = True
        score += intel.get("completion_weight", 0)

        families |= set(intel.get("families", []))
        cwe |= set(intel.get("cwe_classes", []))
        hunt |= set(intel.get("cve_search_tags", []))

    missing = [r for r in ROLE_ORDER if r not in roles]

    anchors, bridges = detect_candidates(findings)

    viability = min(round(score, 2), 1.0)

    band = "LOW"
    if viability >= 0.65:
        band = "HIGH"
    elif viability >= 0.35:
        band = "MED"

    verdict = {
        "exploitability_band": band,
        "killchain_complete": len(missing) == 0,
        "chain_completion": viability,
        "missing_roles": missing,
        "families": sorted(families),
        "cwe_classes": sorted(cwe),
        "hunt_queries": sorted(hunt),
        "anchor_candidates": anchors,
        "bridge_candidates": bridges
    }

    if offensive:
        verdict["hunt_plan"] = infer_missing_links(missing)
    else:
        verdict["hunt_plan"] = []

    return verdict
