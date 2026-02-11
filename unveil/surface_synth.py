from unv.exploit_families import EXPLOIT_FAMILIES

def synthesize(surfaces):
    out = {}

    for s in surfaces or []:
        cls = s.get("surface")
        fam = EXPLOIT_FAMILIES.get(cls)
        if not fam:
            continue

        cur = out.get(cls)
        if not cur:
            out[cls] = {
                "class": cls,
                "impact": fam.get("impact"),
                "intel": {
                    "families": fam.get("families", []),
                    "cwe_classes": fam.get("cwe_classes", []),
                    "cve_search_tags": fam.get("cve_search_tags", []),
                    "killchain_role": fam.get("killchain_role"),
                    "completion_weight": fam.get("completion_weight"),
                }
            }

    return list(out.values())
