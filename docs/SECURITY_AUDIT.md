# Security Audit: Unveil Integration

**Date:** 2025-02  
**Scope:** CLI, daemon, Burp extension, CI/CD, and handling of paths, secrets, and subprocesses.

---

## Summary

| Area | Status | Notes |
|------|--------|--------|
| Daemon binding & auth | **Hardened** | Binds 127.0.0.1 only; target path validated (exists, file or dir). No auth by design (local-only). |
| Daemon path handling | **Hardened** | Target resolved and validated before `run()`; rejects empty, non-existent, or non-file/dir. |
| Zip extraction (IPA/APK) | **Hardened** | Custom `_safe_zip_extract()` rejects path traversal (zip slip); no extraction outside temp dir. |
| Subprocess (CLI/Burp) | **OK** | ProcessBuilder / subprocess.run use list args (no shell); paths passed as single args. |
| Secrets in code | **OK** | No hardcoded API keys or credentials. PYPI_API_TOKEN used only as GitHub Actions secret. |
| CI (release workflow) | **OK** | Token in `secrets.PYPI_API_TOKEN`; not logged. Permissions: contents write for release only. |
| Temp files (Burp) | **OK** | `File.createTempFile()` + `deleteOnExit()`; report path passed to CLI only. |
| Proxy display (Burp) | **OK** | Shows listener (e.g. 0.0.0.0) for user config only; does not bind any server. |

---

## 1. Daemon (`unveil/daemon.py`)

- **Binding:** `host="127.0.0.1"` — server is localhost-only; not exposed to the network.
- **Authentication:** None. By design for local integration; do not bind to 0.0.0.0 or put behind a reverse proxy without adding auth.
- **Path validation (added):** `_validate_target()` resolves the path, requires it to exist, and requires it to be a file or directory. Rejects empty and non-existent paths to avoid information disclosure or unexpected behavior.
- **Recommendation:** If you ever expose the daemon beyond localhost (e.g. team server), add API key or TLS and restrict allowed path prefixes (e.g. `UNVEIL_DAEMON_ALLOW_PATHS`).

---

## 2. Path and file handling

- **Engine `run(target)`:** Accepts a path from CLI or daemon. Daemon now validates target before calling `run()`. CLI path is user-provided at the command line (same trust as any CLI).
- **Zip (IPA/APK):** Extraction uses `_safe_zip_extract()` so that no member path can escape the temp dir (zip slip). Members with `..`, leading `/`, or empty names are skipped.
- **DMG:** Uses `hdiutil` with a temp mount point; mount point is under `tempfile.mkdtemp()`.
- **Static parser / file:** Uses `subprocess.run([...])` with list arguments; path is a single element (no shell, no injection).

---

## 3. Burp extension

- **ProcessBuilder:** `buildUnveilArgs()` builds a list of arguments; target and paths are single list elements (no shell, no injection).
- **Temp report file:** `File.createTempFile("unveil-report-", ".json")` with `deleteOnExit()`; path passed to CLI via `-xj`. Deleted after read.
- **Proxy listener field:** Displays Burp’s listener (e.g. 127.0.0.1:8080 or 0.0.0.0) for user reference only; the extension does not open any network listener.
- **No secrets:** No API keys or credentials in the extension; scan config and report stay in the user’s environment.

---

## 4. CI/CD (GitHub Actions)

- **Release workflow:** Triggered only by tags `v*.*.*`. Builds the package and creates a GitHub Release; then runs `twine upload`.
- **PyPI token:** Stored as repo secret `PYPI_API_TOKEN`; referenced as `secrets.PYPI_API_TOKEN`. Not echoed in logs (GitHub masks secrets by default).
- **Permissions:** `contents: write` is required for creating the release and uploading assets; no broader permissions.

---

## 5. Checklist and report data

- **Checklist scan:** Detects patterns (e.g. passwords, API keys) in discovered files; results are in the report. Report is handled by the same process (CLI/Burp) that runs the scan; no automatic exfiltration.
- **Report contents:** Include paths, asset lists, and optional CVE/search terms. User controls where the report is saved or sent (file, Burp, daemon response).

---

## 6. Recommendations

1. **Daemon:** Keep it bound to 127.0.0.1. If you expose it later, add authentication and path allowlisting.
2. **Secrets:** Keep using GitHub Actions secrets for PyPI; do not put tokens in code or in workflow logs.
3. **Dependencies:** Periodically run `pip audit` / equivalent and update dependencies for known vulnerabilities.
4. **Zip:** The current zip extraction is hardened; if you add other archive types, use the same “resolve and check under dest” pattern.

---

## Changes made in this audit

- **Daemon:** Added `_validate_target()` and use it in `POST /scan`; documented local-only, no-auth design.
- **Engine:** Replaced raw `extractall()` with `_safe_zip_extract()` for IPA/APK to prevent zip slip.
- **Docs:** Added this `SECURITY_AUDIT.md` and referenced it from the daemon module.
