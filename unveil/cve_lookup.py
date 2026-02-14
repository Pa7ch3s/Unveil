"""
P1: Optional CVE lookup by product/version or hunt queries.
Uses NVD API 2.0. Without API key: 5 requests/30s; with NVD_API_KEY: 50/30s.
"""
import os
import re
import time
import json
import urllib.error
import urllib.request
import urllib.parse

# NVD API 2.0: https://nvd.nist.gov/developers/vulnerabilities
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RATE_LIMIT_DELAY = 6.5  # seconds between requests without key
_USER_AGENT = "Unveil/1.0 (CVE lookup; https://github.com/pa7ch3s/unveil)"


def _nvd_request(params, api_key=None):
    """Single NVD API 2.0 request. Returns (data_dict, error_str). API key via header."""
    parts = []
    for k, v in params.items():
        if v is None:
            continue
        if isinstance(v, bool):
            if v:
                parts.append(urllib.parse.quote(str(k)))
            continue
        parts.append(f"{urllib.parse.quote(str(k))}={urllib.parse.quote(str(v))}")
    url = NVD_BASE + ("?" + "&".join(parts) if parts else "")
    req = urllib.request.Request(url)
    req.add_header("User-Agent", _USER_AGENT)
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            retry_after = e.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                time.sleep(min(int(retry_after), 60))
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, str(e)[:100]


def _extract_product_version(query):
    """Heuristic: extract product and optional version from a hunt query string."""
    # e.g. "Electron 8.1.0", "Qt 5.15", "Microsoft .NET Framework 4.8"
    q = (query or "").strip()
    if not q:
        return None, None
    # Try "Product X.Y.Z" or "Product X.Y"
    m = re.match(r"^(.+?)\s+(\d+(?:\.\d+){0,3})$", q)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    # Try "Product < X" or "Product <= X"
    m = re.match(r"^(.+?)\s+[<>]=?\s*(\d+(?:\.\d+)*)$", q)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return q, None


def _parse_cve_item(item, max_summary_len=300):
    """Parse one entry from NVD 2.0 vulnerabilities array. Returns dict or None."""
    cve = item.get("cve") or {}
    # NVD 2.0: cve object has "id" (CVE-ID)
    cve_id = (cve.get("id") or cve.get("cveId") or "").strip()
    if not cve_id:
        return None
    # descriptions: list of {lang, value}
    desc_list = cve.get("descriptions") or []
    summary = ""
    for d in desc_list:
        if (d.get("lang") or "").lower() == "en":
            summary = (d.get("value") or "")[:max_summary_len]
            break
    if not summary and desc_list:
        summary = (desc_list[0].get("value") or "")[:max_summary_len]
    # metrics: optional; cvssMetricV31, cvssMetricV30, cvssMetricV2 (each list of {cvssData: {baseScore}})
    score = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in (metrics.get(key) or []):
            cd = m.get("cvssData") or {}
            if cd.get("baseScore") is not None:
                score = cd["baseScore"]
                break
        if score is not None:
            break
    published = (cve.get("published") or "")[:10]
    return {
        "id": cve_id,
        "summary": summary,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "published": published,
        "score": score,
    }


def lookup_cves_for_query(query, api_key=None, max_results=10):
    """
    Query NVD API 2.0 for CVEs by keyword (product name) and optional version.
    Returns list of {"id", "summary", "url", "published", "score"} (up to max_results).
    """
    product, version = _extract_product_version(query)
    keyword = product or query
    if not keyword:
        return []
    # NVD 2.0: keywordSearch, resultsPerPage (max 2000), noRejected to skip rejected CVEs
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max_results, 50),
        "noRejected": True,
    }
    data, err = _nvd_request(params, api_key=api_key)
    if err or not data:
        return []
    results = []
    for item in data.get("vulnerabilities") or []:
        parsed = _parse_cve_item(item)
        if parsed:
            results.append(parsed)
        if len(results) >= max_results:
            break
    return results


def enrich_report_cve_lookup(report, api_key=None, max_queries=20, max_cves_per_query=5):
    """
    If report has possible_cves or verdict.hunt_queries, optionally call NVD and add
    report["cve_lookup"] = {"queries": [{"query", "cves": [...]}], "error": optional}.
    api_key: from env NVD_API_KEY if None.
    """
    api_key = api_key or os.environ.get("NVD_API_KEY", "").strip() or None
    queries = []
    if report.get("possible_cves"):
        for q in report["possible_cves"][:max_queries]:
            if isinstance(q, str) and q.strip():
                queries.append(q.strip())
    if not queries and report.get("verdict", {}).get("hunt_queries"):
        for q in report["verdict"]["hunt_queries"][:max_queries]:
            if isinstance(q, str) and q.strip():
                queries.append(q.strip())
    queries = list(dict.fromkeys(queries))[:max_queries]
    if not queries:
        return report
    delay = 0 if api_key else _RATE_LIMIT_DELAY
    results = []
    for i, q in enumerate(queries):
        if i > 0 and delay > 0:
            time.sleep(delay)
        cves = lookup_cves_for_query(q, api_key=api_key, max_results=max_cves_per_query)
        results.append({"query": q, "cves": cves})
    report["cve_lookup"] = {"queries": results}
    return report
