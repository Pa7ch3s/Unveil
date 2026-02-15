# Final audit: bugs and hiccups (post P0–P3)

One-time pass over the codebase after implementing the Senior Pentester Audit. Fixes applied and remaining notes.

---

## Fixes applied

### 1. Findings export — dedup key truncation
- **File:** `unveil/findings_export.py`
- **Issue:** Dedup key was `(Title, Path, Snippet)[:200]`; in Python that slices the *tuple* (max 3 elements), not each string, so keys were unbounded and dedup was correct but keys could be very long.
- **Fix:** Key is now `((Title)[:200], (Path)[:200], (Snippet)[:200])` so each part is truncated for a bounded, consistent key.

### 2. Findings export — thick_client path type
- **File:** `unveil/findings_export.py`
- **Issue:** `path = artifacts[0] if artifacts else ""` could yield a non-string (e.g. dict) if the thick_client_findings contract ever changed.
- **Fix:** Coerce to string: if `path` is not a string, use `str(path)` (or empty).

### 3. APK manifest — relative path
- **File:** `unveil/engine.py`
- **Issue:** `get_apk_manifest_summary(target)` was called with the raw `target`; if it was relative (e.g. `./app.apk`) and the process cwd differed (e.g. Burp daemon), `Path(apk_path).is_file()` or aapt could fail.
- **Fix:** Call with `get_apk_manifest_summary(str(Path(target).resolve()))` so the APK path is always absolute.

### 4. DB summary — SQLite URI on Windows
- **File:** `unveil/db_summary.py`
- **Issue:** `sqlite3.connect(f"file:{path}?mode=ro", uri=True)` with a Windows path like `C:\foo\bar.db` is not a valid URI.
- **Fix:** Use `Path(path).resolve().as_uri()` so the path becomes a proper `file:///` URI, then append `?mode=ro`.

### 5. CLI export-findings — parent directory
- **File:** `unveil/cli.py`
- **Issue:** Writing to e.g. `-xf reports/scan/findings.csv` could fail if `reports/scan` did not exist.
- **Fix:** Create parent with `path.resolve().parent.mkdir(parents=True, exist_ok=True)` before writing, only when parent is not the same as the resolved path (avoids creating “.” or root).

### 6. Burp — fs_usage paths with spaces
- **File:** `unveil-burp/.../UnveilTab.java`
- **Issue:** “Copy fs_usage one-liner” concatenated paths with spaces; paths containing spaces would break the shell command.
- **Fix:** Paths that contain a space or single quote are wrapped in single quotes, and single quotes in the path are escaped as `'\"'\"'` for bash.

---

## Checked and left as-is

- **Empty report / all branches:** `_empty_report` and every report branch (APK, JAR, single-file, directory) include the same P0–P3 keys (`update_refs`, `tls_pinning_hints`, `suggested_order`, `apk_manifest`, `credential_hints`, `db_summary` where applicable).
- **Burp backward compatibility:** Old reports without `tag` in `non_http_refs` still render; `str(o.get("tag"))` yields `""` when missing. Same for optional keys in other sections.
- **Credential hints:** `_collect_imports_from_results` is a generator; iteration in `build_credential_hints` is correct. Type hint says `List[tuple]` but usage is correct.
- **Export findings CSV:** Rows come from `_row()` with fixed keys; no mixed schemas, so `DictWriter` is safe.
- **Export findings MD:** Table has 7 columns (Source omitted to keep table narrow); data is still in the row and in CSV export.

---

## Optional / future improvements

- **Force (-f):** Engine accepts `force` and it is documented as reserved; no behaviour yet. When implementing (e.g. skip signature checks), gate the relevant branches on `force`.
- **APK manifest:** Uses aapt/aapt2 when available; if missing, report has `note` and empty sections. No change needed for this audit.
- **ProcMon/fs_usage:** Paths to watch can be very long; ProcMon has its own limits. Current “Copy for ProcMon” and “Copy fs_usage” are best-effort; no code change.
- **Import summary / packed_entropy:** Already in report; Burp tabs added. No bug found.

---

## Summary

| Area            | Status | Notes                                      |
|-----------------|--------|--------------------------------------------|
| Findings export | Fixed  | Dedup key, path type, parent dir creation  |
| APK manifest    | Fixed  | Absolute path for aapt                     |
| DB summary      | Fixed  | URI for SQLite on Windows                  |
| Burp fs_usage   | Fixed  | Quoting for paths with spaces              |
| Backward compat | OK     | Old reports load in Burp                   |
| Force (-f)      | Doc    | Reserved; no behaviour yet                 |

No known remaining bugs from this audit. Regression: run a directory scan, single-file scan, and APK scan; export findings to CSV and MD; open report in Burp and use Export findings, Copy evidence, Copy launch command, Copy fs_usage, and DB/Credential/Update refs tabs.
