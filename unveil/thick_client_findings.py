"""
Dynamic thick-client findings: what was actually found in the scan, in pentest terms.
Surfaces concrete results (Electron config, .NET refs, certs, persistence paths, chains with matched paths)
so the report is not just placeholder labels but "we found X at Y; try Z."
"""
from typing import List, Dict, Any

from unveil.missing_link_engine import ROLE_LABELS, SURFACE_LABELS


def build_thick_client_findings(
    verdict: dict,
    findings: list,
    electron_info: dict,
    dotnet_findings: list,
    cert_findings: list,
    attack_graph: dict,
    discovered_assets: dict,
    chainability: list,
    max_findings: int = 80,
) -> List[Dict[str, Any]]:
    """
    Build a list of thick-client-specific findings from actual scan data.
    Each entry: category, title, summary, artifacts[], hunt_suggestion, surface, role, severity.
    Categories: Electron, Qt, .NET, Persistence, Certificates, Chain, Other.
    """
    out: List[Dict[str, Any]] = []

    # ---- Electron: from electron_info + findings with electron_* surfaces
    if electron_info:
        ei = electron_info
        version = ei.get("version") or "unknown"
        parts = [f"Electron {version}"]
        if "nodeIntegration" in ei:
            parts.append(f"nodeIntegration={ei['nodeIntegration']}")
        if "contextIsolation" in ei:
            parts.append(f"contextIsolation={ei['contextIsolation']}")
        if "sandbox" in ei:
            parts.append(f"sandbox={ei['sandbox']}")
        if ei.get("preload"):
            parts.append(f"preload={ei['preload']}")
        if ei.get("main"):
            parts.append(f"main={ei['main']}")
        if ei.get("asar") is not None:
            parts.append("asar packed" if ei.get("asar") else "asar unpacked/disabled")
        summary = "; ".join(parts)
        hunt = "Preload path override, ASAR write, or renderer RCE if nodeIntegration/contextIsolation weak."
        out.append({
            "category": "Electron",
            "title": "Electron app detected",
            "summary": summary,
            "artifacts": [f"package.json (version {version})"],
            "hunt_suggestion": hunt,
            "surface": "electron_preload",
            "role": "BLADE",
            "severity": "info",
        })

    # ---- Findings: surfaces we actually tagged (class + paths list)
    seen_class = set()
    for f in (findings or []):
        if not isinstance(f, dict):
            continue
        cls = f.get("class") or ""
        paths = f.get("surface") or []  # list of paths for this surface class
        if isinstance(paths, str):
            paths = [paths] if paths else []
        anchor = (f.get("anchor") or "").strip()
        if not cls or cls in seen_class:
            continue
        seen_class.add(cls)
        label = SURFACE_LABELS.get(cls) or cls
        if cls.startswith("electron"):
            cat = "Electron"
            role = "BLADE" if "preload" in cls or "asar" in cls else "BRIDGE"
        elif "qt" in cls:
            cat = "Qt"
            role = "ANCHOR"
        elif cls == "dotnet_managed":
            cat = ".NET"
            role = "ANCHOR"
        elif "persistence" in cls or "launch" in cls or "windows" in cls or "linux" in cls:
            cat = "Persistence"
            role = "ANCHOR"
        elif cls == "jar_archive":
            cat = "JAR"
            role = "ANCHOR"
        else:
            cat = "Other"
            role = ""
        summary = f"Surface: {label}; {len(paths)} path(s) found."
        if anchor:
            summary += f" Reentry: {anchor}."
        out.append({
            "category": cat,
            "title": label,
            "summary": summary,
            "artifacts": [p for p in paths if isinstance(p, str) and p.strip()][:15],
            "hunt_suggestion": f"Confirm writable paths or override for {label}.",
            "surface": cls,
            "role": role,
            "severity": "info",
        })
        if len(out) >= max_findings:
            return out[:max_findings]

    # ---- .NET: from dotnet_findings
    for d in (dotnet_findings or [])[:20]:
        if not isinstance(d, dict):
            continue
        path = (d.get("path") or "").strip()
        name = d.get("assembly_name") or "unknown"
        ver = d.get("version") or ""
        hints = d.get("dangerous_hints") or []
        config_hints = d.get("config_hints") or []
        summary = f".NET assembly: {name}"
        if ver:
            summary += f" ({ver})"
        if hints:
            summary += "; " + "; ".join(hints[:5])
        if config_hints:
            summary += "; config: " + ", ".join(config_hints[:3])
        out.append({
            "category": ".NET",
            "title": f".NET assembly: {name}",
            "summary": summary,
            "artifacts": [path] if path else [],
            "hunt_suggestion": "Check .config for Type.GetType, remoting; test deserialization if refs present.",
            "surface": "dotnet_managed",
            "role": "ANCHOR",
            "severity": "medium" if (hints or config_hints) else "info",
        })
        if len(out) >= max_findings:
            return out[:max_findings]

    # ---- Certificates
    for c in (cert_findings or [])[:15]:
        if not isinstance(c, dict):
            continue
        path = (c.get("path") or "").strip()
        expired = c.get("expired", False)
        self_signed = c.get("self_signed", False)
        key_bits = c.get("key_bits")
        summary = "Certificate"
        if expired:
            summary += " (expired)"
        if self_signed:
            summary += " (self-signed)"
        if key_bits:
            summary += f" {key_bits}-bit"
        out.append({
            "category": "Certificates",
            "title": "Certificate in bundle",
            "summary": summary,
            "artifacts": [path] if path else [],
            "hunt_suggestion": "MITM or cert pinning bypass if app trusts this cert or disables validation.",
            "surface": "network_mitm",
            "role": "BRIDGE",
            "severity": "medium" if (expired or self_signed) else "info",
        })
        if len(out) >= max_findings:
            return out[:max_findings]

    # ---- Attack graph chains that have matched_paths (concrete chain step)
    chains = (attack_graph or {}).get("chains") or []
    for ch in chains:
        if not isinstance(ch, dict):
            continue
        role = ch.get("missing_role") or ""
        surface = ch.get("suggested_surface") or ""
        matched = ch.get("matched_paths") or []
        role_label = ROLE_LABELS.get(role) or role
        surface_label = SURFACE_LABELS.get(surface) or surface
        if matched:
            summary = f"Chain step: {role_label} — {surface_label}; {len(matched)} path(s) matched."
            out.append({
                "category": "Chain",
                "title": f"{role}: {surface_label}",
                "summary": summary,
                "artifacts": matched[:10],
                "hunt_suggestion": ch.get("hunt_targets") or ch.get("reason") or "Use suggested payloads for this surface.",
                "surface": surface,
                "role": role,
                "severity": "high",
            })
        else:
            summary = f"Missing: {role_label} — {surface_label}. No paths matched yet."
            out.append({
                "category": "Chain",
                "title": f"Missing {role}: {surface_label}",
                "summary": summary,
                "artifacts": [],
                "hunt_suggestion": ch.get("hunt_targets") or ch.get("reason") or "",
                "surface": surface,
                "role": role,
                "severity": "info",
            })
        if len(out) >= max_findings:
            return out[:max_findings]

    # ---- Missing roles (gap): what to hunt
    missing = (verdict or {}).get("missing_roles") or []
    for role in missing:
        role_label = ROLE_LABELS.get(role) or role
        out.append({
            "category": "Chain",
            "title": f"Gap: {role_label}",
            "summary": f"No {role} surface confirmed yet. Hunt for {role_label.lower()}.",
            "artifacts": [],
            "hunt_suggestion": f"Look for persistence (ANCHOR), lateral movement (BRIDGE), or code execution (BLADE) surfaces.",
            "surface": "",
            "role": role,
            "severity": "info",
        })
        if len(out) >= max_findings:
            return out[:max_findings]

    return out[:max_findings]
