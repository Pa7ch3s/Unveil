# CLI and UI improvements (code and behavior)

This doc identifies **concrete code and behavior changes** to the CLI and Burp UI from multiple angles: validation, errors, progress, consistency, and missing behavior. These are implementation-level improvements, not documentation-only.

---

## 1. CLI

### 1.1 Validation and errors

| Gap | Current behavior | Change |
|-----|------------------|--------|
| **Target path not validated** | `engine.run(target)` uses `Path(target)`; if path doesn’t exist we fall through to directory mode and eventually get empty results with no explanation. | In `engine.run()` at entry: if path does not exist, return `_empty_report(target, reason="TARGET_NOT_FOUND")` or raise a clear `ValueError("Target path does not exist: ...")`. In `cli.main()` catch and print a one-line error instead of traceback. |
| **No try/except around run()** | Any exception from `run()` (e.g. from `analyze()`, file I/O) propagates and the CLI dumps a traceback. | In `cli.main()`: wrap `run(...)` in try/except; on exception print a short message to stderr (e.g. "Unveil failed: <message>") and exit with non-zero. Optionally with `-V` re-raise or print traceback. |
| **Baseline/cve failures silent** | If `apply_baseline` or reading baseline file fails, we `except Exception: pass` and continue with unmodified report. | At least log to stderr that baseline was skipped; optionally fail with a clear message if `--baseline` was explicitly given. |

### 1.2 Help and discoverability

| Gap | Current behavior | Change |
|-----|------------------|--------|
| **-e / -O meaning** | Help text is one line each; new users don’t know “extended” vs “offensive” or when to use both. | Extend `-e` help: “Use with directory/.app for persistence and helper discovery; use -O for full attack graph and chains.” Extend `-O`: “Exploit-chain modeling and attack graph; use with -e for best coverage.” |
| **Single file vs directory** | Not stated in -C help. | Add to `-C` help: “Directory or .app for full recon; single file (e.g. .exe) for one binary.” |

### 1.3 Output and progress

| Gap | Current behavior | Change |
|-----|------------------|--------|
| **Progress only on stderr** | `tick()` writes to stderr; with `-q` there’s no output until the end. Long scans look stuck. | Consider a single “Scanning …” line at start (stderr) when not quiet, or document that progress is on stderr. |
| **Empty report reason** | When target is missing or DMG/IPA/APK fails, report has `exploitability_band` like "UNKNOWN" or empty findings; no explicit “why” in the JSON. | Add an optional `metadata.error` or `metadata.skip_reason` (e.g. "TARGET_NOT_FOUND", "DMG_MOUNT_FAILED") so UI and scripts can show a clear reason. |

---

## 2. Burp UI

### 2.1 Scan failures and recovery

| Gap | Current behavior | Change |
|-----|------------------|--------|
| **Process start vs exit code** | When the unveil process fails to *start* (e.g. not in PATH), we catch an exception and call `onUnveilError` with install hint. When the process *starts* but exits non-zero, we only show “Scan failed” and “Check options or unveil CLI” with no install hint. | In `runUnveil`, when `exit == 127` (command not found on Unix) or equivalent, show the same install + path hint as in `onUnveilError` (e.g. in summaryArea and statusLabel) so “unveil not found” is handled even when the process builder starts but the exec fails. |
| **Target path not validated before scan** | User can enter a non-existent path and click Scan; we only find out after the CLI fails or returns empty. | Before submitting the scan task, check that the path exists (File.exists() and isDirectory() or isFile()); if not, set statusLabel to “Path does not exist” and optionally show a short message in summaryArea; do not start the process. |
| **Daemon connection errors** | “Could not call daemon” shows the exception message; no hint to check URL or start daemon. | Append a one-liner: “Check that the daemon is running (e.g. run ‘unveil’ or ‘python -m unveil.daemon’) and the URL is correct.” |

### 2.2 Consistency and feedback

| Gap | Current behavior | Change |
|-----|------------------|--------|
| **Scan button state** | Scan disables the button; on failure we re-enable. If the user switches tab or does something else during scan, it’s not obvious that a scan is in progress. | Keep current behavior; optionally show “Scanning &lt;target&gt;…” in statusLabel (already done) and ensure it’s visible (e.g. not scrolled away). |
| **Export/SARIF reuse of unveil** | Export SARIF and Export HTML run the unveil process again; if unveil isn’t found we get a generic error. | Reuse the same “not found” detection and install hint as for Scan when the export process fails to start or exits 127. |
| **Empty report after “Done”** | When exit is 0 but the report file is empty or invalid JSON, we show “Scan finished but no report file was produced” or parse error. We don’t distinguish “CLI wrote nothing” from “CLI crashed after starting”. | Already reasonable; optionally in applyReport on parse failure, suggest “Try running the CLI manually: unveil -C <path> -q -xj out.json” to debug. |

### 2.3 Data and usability

| Gap | Current behavior | Change |
|-----|------------------|--------|
| **No “why” for empty verdict** | When the report has few or no surfaces, the user doesn’t know if the target is unsupported, the path was wrong, or limits capped the scan. | If the report has `metadata.skip_reason` or `metadata.error`, show it in the Summary (e.g. “Target not found” or “DMG mount failed”). If findings are empty and no error, show a short hint: “No surfaces found. Try -e -O, or a different target (e.g. Electron/Qt/.NET app).” |
| **Chainability / tables** | Already improved with filters and context menu. | No change needed for this pass. |

---

## 3. Engine (shared)

| Gap | Current behavior | Change |
|-----|------------------|--------|
| **Early target check** | No existence check; wrong path leads to empty or confusing results. | At start of `run(target, ...)`: `p = Path(target).resolve()`; if not `p.exists()`, return `_empty_report(target, reason="TARGET_NOT_FOUND")` and include e.g. `metadata["error"] = "Target path does not exist"` so CLI and Burp can display it. |
| **Empty report shape** | `_empty_report()` already has a consistent shape; we don’t set an error field. | Add `metadata["error"]` or `metadata["skip_reason"]` in `_empty_report` and in any early-return path (DMG, IPA, APK fail) so UI can show the reason. |

---

## 4. Implementation priority

1. **Engine + CLI:** Validate target exists at start of `run()`; return structured empty report with reason; CLI catch exceptions and print clean error.
2. **Burp:** Validate path before starting scan; on exit 127 (or process start failure) show install/path hint in the same way as current `onUnveilError`.
3. **CLI:** Improve `-C`, `-e`, `-O` help text.
4. **Engine:** Set `metadata.error` / `skip_reason` on all early exits and empty reports.
5. **Burp:** In Summary, display `metadata.error` when present; optional one-line hint when findings are empty and no error.
6. **Daemon error:** Append “check daemon running and URL” to daemon failure message.

Implementing (1)–(2) and (4)–(5) gives the largest gain for new users and for debugging failed runs.
