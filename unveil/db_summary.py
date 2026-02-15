"""
P2: DB summary for discovered .db/.sqlite — table names and optional "possible credentials" hint.
Read-only; caps size/count to avoid heavy I/O.
"""
import sqlite3
from pathlib import Path
from typing import Dict, List, Any

MAX_DB_FILES = 30
MAX_TABLE_NAMES = 100
CREDENTIAL_TABLE_NAMES = ("user", "pass", "credential", "token", "auth", "login", "account", "session", "secret")


def _possible_credentials_hint(tables: List[str]) -> str:
    """If any table name looks like it might hold credentials, return a short hint."""
    lower = [t.lower() for t in tables]
    for kw in CREDENTIAL_TABLE_NAMES:
        if any(kw in t for t in lower):
            return f"Possible credentials table (name contains '{kw}'); consider dumping."
    return ""


def get_db_summary(discovered_assets: Dict[str, List], max_files: int = MAX_DB_FILES) -> List[Dict[str, Any]]:
    """
    For each .db/.sqlite in discovered_assets['data'], list table names (PRAGMA table_list)
    and set possible_credentials_hint if any table name suggests credentials.
    """
    out: List[Dict[str, Any]] = []
    paths = (discovered_assets.get("data") or [])[:max_files]
    for path in paths:
        if not path or not isinstance(path, str):
            continue
        p = Path(path)
        if p.suffix.lower() not in (".db", ".sqlite", ".sqlite3"):
            continue
        if not p.is_file():
            continue
        try:
            if p.stat().st_size > 50 * 1024 * 1024:  # skip > 50MB
                out.append({"path": path, "tables": [], "possible_credentials_hint": "File too large; skipped."})
                continue
        except OSError:
            continue
        tables: List[str] = []
        try:
            # Use resolved URI so Windows and relative paths work
            uri = Path(path).resolve().as_uri()
            conn = sqlite3.connect(f"{uri}?mode=ro", uri=True)
            try:
                cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
                for row in cur:
                    if row and row[0] and row[0] not in tables:
                        tables.append(row[0])
                        if len(tables) >= MAX_TABLE_NAMES:
                            break
            finally:
                conn.close()
        except Exception:
            tables = []
        hint = _possible_credentials_hint(tables) if tables else ""
        out.append({
            "path": path,
            "tables": tables[:MAX_TABLE_NAMES],
            "possible_credentials_hint": hint or None,
        })
    return out
