"""
Chainability: link extracted refs to discovered assets so we can report "file A references B; B is in scope".
"""
from pathlib import Path


def _normalize_for_match(p):
    """Normalize path for comparison (lowercase, resolve if possible, use forward slashes)."""
    if not p:
        return ""
    p = str(p).lower().replace("\\", "/")
    try:
        return str(Path(p).resolve()).lower().replace("\\", "/")
    except Exception:
        return p


def build_chainability(extracted_refs, discovered_assets):
    """
    For each ref in extracted_refs, check if it matches any path in discovered_assets (by type).
    Returns list of {"file": source_path, "ref": ref_value, "in_scope": bool, "matched_type": type or null}.
    """
    out = []
    if not discovered_assets:
        return out
    # Build set of normalized paths and basenames from all discovered assets
    all_paths = set()
    all_basenames = set()
    for paths in discovered_assets.values():
        if not isinstance(paths, list):
            continue
        for p in paths:
            try:
                all_paths.add(_normalize_for_match(p))
                all_basenames.add(Path(p).name.lower())
            except Exception:
                pass
    seen_ref_key = set()
    for item in extracted_refs or []:
        source = item.get("file") or ""
        for ref in (item.get("refs") or []):
            ref_str = (ref or "").strip()
            if not ref_str or len(ref_str) > 500:
                continue
            ref_key = (source, ref_str)
            if ref_key in seen_ref_key:
                continue
            seen_ref_key.add(ref_key)
            norm_ref = _normalize_for_match(ref_str)
            ref_basename = Path(ref_str).name.lower() if ref_str else ""
            in_scope = norm_ref in all_paths or ref_basename in all_basenames
            if not in_scope and ("/" in ref_str or "\\" in ref_str):
                # Partial match: ref ends with a path segment that appears in discovered
                for ap in all_paths:
                    if ap.endswith(norm_ref) or norm_ref.endswith(ap):
                        in_scope = True
                        break
            matched_type = None
            if in_scope:
                for atype, paths in discovered_assets.items():
                    if not isinstance(paths, list):
                        continue
                    for p in paths:
                        if _normalize_for_match(p) == norm_ref or Path(p).name.lower() == ref_basename:
                            matched_type = atype
                            break
                    if matched_type:
                        break
            out.append({
                "file": source,
                "ref": ref_str,
                "in_scope": in_scope,
                "matched_type": matched_type,
            })
    return out[:500]  # cap for report size
