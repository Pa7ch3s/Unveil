from unv.exploit_families import EXPLOIT_FAMILIES

def synthesize(surfaces):
    out = {}
    for s in surfaces:
        fam = EXPLOIT_FAMILIES.get(s["class"])
        if not fam:
            continue

        k = s["class"]
        cur = out.get(k)
        if not cur:
            out[k] = {
                "class": k,
                "impact": s.get("impact"),
                "intel": {
                    "families": fam["families"],
                    "cwe_classes": fam["cwe_classes"],
                    "cve_search_tags": fam["cve_search_tags"],
                    "killchain_role": fam["killchain_role"],
                    "completion_weight": fam["completion_weight"]
                }
            }
            cur = out[k]

    return list(out.values())
