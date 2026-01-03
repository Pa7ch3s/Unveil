from unv.exploit_families import EXPLOIT_FAMILIES

def synthesize(surfaces):
    out = {}

    for s in surfaces:
        cls = s.get("class") or s.get("surface")
        fam = EXPLOIT_FAMILIES.get(cls)
        if not fam:
            continue

        cur = out.get(cls)
        if not cur:
            out[cls] = {
                "class": cls,
                "impact": s.get("impact"),
                "intel": {
                    "families": fam["families"],
                    "cwe_classes": fam["cwe_classes"],
                    "cve_search_tags": fam["cve_search_tags"],
                    "killchain_role": fam["killchain_role"],
                    "completion_weight": fam["completion_weight"]
                }
            }

    return list(out.values())