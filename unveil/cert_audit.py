"""
Cert audit for discovered certs: validity, expiry, self-signed. Uses openssl when available.
"""
from pathlib import Path
import subprocess
import re
from datetime import datetime


def _run_openssl(cert_path: str) -> tuple:
    try:
        r = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode != 0:
            return None, None
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception:
        return None, None


def _parse_openssl_text(text: str) -> dict:
    """Parse openssl x509 -text output for Not Before, Not After, Subject, Issuer, key size, algorithm."""
    out = {}
    for line in text.splitlines():
        if "Not Before" in line:
            m = re.search(r"Not Before\s*:\s*(.+)", line)
            if m:
                out["not_before"] = m.group(1).strip()
        if "Not After" in line:
            m = re.search(r"Not After\s*:\s*(.+)", line)
            if m:
                out["not_after"] = m.group(1).strip()
        if "Subject:" in line:
            m = re.search(r"Subject:\s*(.+)", line)
            if m:
                out["subject"] = m.group(1).strip()[:200]
        if "Issuer:" in line:
            m = re.search(r"Issuer:\s*(.+)", line)
            if m:
                out["issuer"] = m.group(1).strip()[:200]
        if "Public-Key:" in line:
            m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", line)
            if m:
                out["key_bits"] = int(m.group(1))
        if "RSA Public-Key:" in line:
            m = re.search(r"RSA Public-Key:\s*\((\d+)\s*bit\)", line)
            if m:
                out["key_bits"] = int(m.group(1))
                out["algorithm"] = "RSA"
        if "ASN1 OID:" in line and "algorithm" not in out:
            if "RSA" in line:
                out["algorithm"] = "RSA"
            elif "EC" in line or "id-ecPublicKey" in line:
                out["algorithm"] = "EC"
    return out


def _is_self_signed(text: str) -> bool:
    """Heuristic: Subject and Issuer are the same."""
    subj = re.search(r"Subject:\s*(.+)", text)
    iss = re.search(r"Issuer:\s*(.+)", text)
    if subj and iss:
        return subj.group(1).strip() == iss.group(1).strip()
    return False


def _expired(not_after_str: str) -> bool:
    """Try to parse date and return True if expired."""
    if not not_after_str:
        return False
    # OpenSSL format: "Feb 13 12:00:00 2026 GMT" or similar
    try:
        # Remove GMT and try common formats
        s = not_after_str.replace(" GMT", "").strip()
        for fmt in ("%b %d %H:%M:%S %Y", "%Y %b %d %H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                return dt.timestamp() < datetime.now().timestamp()
            except ValueError:
                continue
    except Exception:
        pass
    return False


def audit_cert(path: str) -> dict:
    """
    Audit a single cert file. Returns dict with path, subject, issuer, not_after, expired, self_signed, error.
    """
    p = Path(path)
    if not p.is_file() or p.stat().st_size > 1024 * 1024:
        return {"path": path, "error": "skip"}
    code, text = _run_openssl(str(p))
    if code is None or not text:
        return {"path": path, "error": "openssl failed or not available"}
    parsed = _parse_openssl_text(text)
    if not parsed:
        return {"path": path, "error": "could not parse"}
    not_after = parsed.get("not_after") or ""
    expired = _expired(not_after)
    self_signed = _is_self_signed(text)
    return {
        "path": path,
        "subject": parsed.get("subject") or "",
        "issuer": parsed.get("issuer") or "",
        "not_before": parsed.get("not_before") or "",
        "not_after": not_after,
        "expired": expired,
        "self_signed": self_signed,
        "key_bits": parsed.get("key_bits"),
        "algorithm": parsed.get("algorithm") or "",
    }


def run_cert_audit(discovered_assets: dict, max_certs: int = 50) -> list:
    """
    Run cert audit on discovered_assets["cert"] paths. Returns list of audit dicts.
    """
    paths = (discovered_assets or {}).get("cert") or []
    out = []
    for path in paths[:max_certs]:
        try:
            r = audit_cert(path)
            if r.get("error") == "skip":
                continue
            out.append(r)
        except Exception:
            continue
    return out
