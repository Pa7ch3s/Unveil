"""
Attack graph: chains (missing role → surface → hunt targets) and sendable URLs for Repeater.
"""
import re
from typing import List, Dict, Any

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
        chains.append({
            "missing_role": missing_role,
            "suggested_surface": suggested_surface,
            "hunt_targets": hunt_targets_str,
            "reason": reason,
            "matched_paths": entry.get("matched_paths") or [],
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

    return {
        "chains": chains,
        "sendable_urls": sendable_urls[:200],
    }
