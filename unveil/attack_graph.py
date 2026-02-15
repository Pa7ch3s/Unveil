"""
Attack graph: chains (missing role → surface → hunt targets) and sendable URLs for Repeater.
Includes plain-language role labels for thick-client testing.
"""
import re
from typing import List, Dict, Any

from unveil.missing_link_engine import ROLE_LABELS, ROLE_DESCRIPTIONS, SURFACE_LABELS
from unveil.payloads import get_payloads_for_surface

URL_PATTERN = re.compile(r"https?://[^\s\]\"'<>)\},]+", re.IGNORECASE)


def _extract_urls(text: str) -> List[str]:
    """Return list of http(s) URLs found in text."""
    if not text:
        return []
    return list(set(URL_PATTERN.findall(text)))


def build_attack_graph(
    verdict: dict,
    chainability: list,
    extracted_refs: list,
    discovered_html: list,
) -> dict:
    """
    Build attack graph for report: chains (role → surface → targets) and sendable URLs.
    sendable_urls: only http(s) URLs, for one-click Send to Repeater.
    """
    chains = []
    sendable_urls_seen = set()
    sendable_urls: List[Dict[str, str]] = []

    # ---- Chains from hunt_plan
    hunt_plan = (verdict or {}).get("hunt_plan") or []
    for entry in hunt_plan:
        if not isinstance(entry, dict):
            continue
        missing_role = entry.get("missing_role") or ""
        suggested_surface = entry.get("suggested_surface") or ""
        hunt_targets_str = entry.get("hunt_targets") or ""
        reason = entry.get("reason") or ""
        # Parse any URLs from hunt_targets for sendable list
        for url in _extract_urls(hunt_targets_str):
            url_norm = url.rstrip(".,;:)")
            if url_norm not in sendable_urls_seen and url_norm.startswith(("http://", "https://")):
                sendable_urls_seen.add(url_norm)
                sendable_urls.append({"url": url_norm, "source": "hunt_plan", "label": suggested_surface or missing_role})
        role_label = ROLE_LABELS.get(missing_role) or missing_role
        role_description = ROLE_DESCRIPTIONS.get(missing_role) or ""
        component_label = SURFACE_LABELS.get(suggested_surface) or suggested_surface or role_label
        suggested_payloads = get_payloads_for_surface(suggested_surface)
        matched_paths = entry.get("matched_paths") or []
        # P0: confidence for prioritisation (high = paths matched; low = no paths yet)
        confidence = "high" if len(matched_paths) > 0 else "low"
        chains.append({
            "missing_role": missing_role,
            "missing_role_label": role_label,
            "missing_role_description": role_description,
            "suggested_surface": suggested_surface,
            "component_label": component_label,
            "hunt_targets": hunt_targets_str,
            "reason": reason,
            "matched_paths": matched_paths,
            "suggested_payloads": suggested_payloads,
            "confidence": confidence,
        })

    # ---- Sendable URLs from extracted_refs
    for item in (extracted_refs or []):
        if not isinstance(item, dict):
            continue
        file_path = item.get("file") or ""
        for ref in (item.get("refs") or []):
            if not isinstance(ref, str):
                continue
            for url in _extract_urls(ref):
                url_norm = url.rstrip(".,;:)")
                if url_norm not in sendable_urls_seen and url_norm.startswith(("http://", "https://")):
                    sendable_urls_seen.add(url_norm)
                    sendable_urls.append({"url": url_norm, "source": "extracted_ref", "label": file_path[:80]})

    # Suggested order: ANCHOR then BRIDGE then BLADE; within role, chains with matched_paths first
    ROLE_ORDER = ("ANCHOR", "BRIDGE", "BLADE")

    def chain_sort_key(c):
        role = c.get("missing_role") or ""
        role_idx = ROLE_ORDER.index(role) if role in ROLE_ORDER else 99
        has_paths = len(c.get("matched_paths") or []) > 0
        return (role_idx, 0 if has_paths else 1)

    chains.sort(key=chain_sort_key)

    return {
        "chains": chains,
        "sendable_urls": sendable_urls[:200],
    }
