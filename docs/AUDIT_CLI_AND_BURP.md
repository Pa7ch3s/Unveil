# Full audit — CLI + Burp extension (tab not appearing)

**Date:** 2026-02  
**Scope:** Why the Unveil Burp tab may not appear; consistency between CLI and Burp; code quality.

---

## 1. Burp extension — tab not appearing

### 1.1 Root cause analysis

The extension shows as **Loaded** in Burp (Extensions → Installed) but the **Unveil** tab did not appear. Possible causes:

| Cause | Explanation |
|-------|-------------|
| **Exception during tab creation** | `UnveilTab` constructor or `getTabComponent()` throws. Registration was done only *after* creating the component and applying theme, so any failure meant no tab. |
| **applyThemeToComponent throws** | Theme is applied recursively to the whole tree. In some Burp/API versions or with complex components, this can throw and previously prevented `registerSuiteTab` from being called. |
| **Proxy detection in constructor** | Previously `detectProxyListener()` ran in the constructor (reflection on Burp’s `exportProjectOptionsAsJson`). If that API changed or was missing, the constructor could throw. (Already fixed by deferring proxy detection.) |
| **Preferences / security** | `Preferences.userRoot().node(...)` can throw in restricted environments. It is already inside a try/catch in `loadPreferences()`. |

### 1.2 Fixes applied

1. **Register tab first, theme second**  
   The extension now calls `registerSuiteTab("Unveil", component)` **before** `applyThemeToComponent(component)`. If theme application throws, the tab is already registered and visible.

2. **Theme application non-fatal**  
   `applyThemeToComponent` is wrapped in its own try/catch; failure is logged but does not prevent the tab from showing.

3. **Fallback error panel**  
   If `UnveilTab` construction throws, the extension builds a minimal panel showing the exception message and stack trace and registers **that** as the "Unveil" tab. So:
   - The tab **always** appears (either full UI or error panel).
   - The user can read the error in the tab and in Extensions → Unveil → Errors.

4. **Full stack trace in Burp log**  
   Any throwable is logged to Burp’s extension error log with full stack trace for easier debugging.

5. **Proxy detection deferred**  
   Proxy listener detection no longer runs in the constructor; it runs later on the EDT. Constructor no longer depends on Burp’s internal export API.

### 1.3 What to do if the tab still doesn’t appear

- **Reload the extension** using the JAR built after these changes:  
  `unveil-burp/build/libs/unveil-burp-0.7.3.jar`
- **Check Extensions → Unveil → Errors** (and the main **Errors** tab) for the logged exception.
- If you see the **Unveil** tab but it shows an error panel, the message and stack trace there are the root cause (e.g. missing class, API mismatch, Preferences failure).

### 1.4 Manifest and loading

- **Service loader:** `META-INF/services/burp.api.montoya.BurpExtension` → `burp.UnveilExtension`. Present in the built JAR; Burp uses this to instantiate the extension.
- **Manifest:** `Burp-Extension-Name`, `Burp-Extension-Expected-API-Version: 2023.8`. Correct for Montoya.
- **Entry point:** `UnveilExtension` implements `BurpExtension`, has a public no-arg constructor, and `initialize(MontoyaApi api)` runs tab creation on the EDT via `SwingUtilities.invokeLater`. No missing or wrong entry point found.

### 1.5 API version

- Extension is built against **montoya-api:2023.8**.
- If you use a much newer Burp (e.g. 2025+), the runtime API may differ. If the tab still fails after the fixes above, try updating the dependency in `build.gradle.kts` to match your Burp version (see [Maven Central](https://central.sonatype.com/artifact/net.portswigger.burp.extensions/montoya-api)) and rebuild.

---

## 2. CLI audit

### 2.1 Entry point and version

- **Entry:** `unveil/cli.py` → `main()`; version from `importlib.metadata.version("unveil")` with fallback `"0.10.2"`.
- **Banner:** Read from `unveil/assets/banner.txt` if present; version printed on startup.
- **Args:** `-C` (required), `-e`, `-O`, `-f`, `-q`, `-V`, `--max-files`, `--max-size-mb`, `--max-per-type`, `-xh`/`-xj`/`-xx`/`-xs`, `--baseline`, `--cve`, `--cve-lookup`. All wired through to parser and used.

### 2.2 CLI vs engine

- `engine.run()` is called with: `target`, `extended`, `offensive`, `max_files`, `max_size_mb`, `max_per_type`, `cve_lookup`.
- **Gap:** CLI has `-f` (force) and `args.f` is parsed but **not** passed to `engine.run()`. The engine does not define a `force` parameter. So `-f` is currently a no-op in the CLI. Either add a `force` argument to `engine.run()` and use it (e.g. for unsigned/malformed binaries), or document that `-f` is reserved for future use.

### 2.3 Error handling

- Scan errors: `run()` can return a report with `metadata.error`; CLI exits 1 and optionally prints report.
- Exceptions in `main()`: caught, message written to stderr, exit 1; with `-V`/verbose the exception is re-raised.
- Baseline: `apply_baseline` is in a try/except; failure is ignored (no exit, no message). Consider at least logging.

### 2.4 Export and baseline

- Exports (`-xh`, `-xj`, `-xx`, `-xs`) and baseline application run **after** `run()` and after optional `possible_cves` / baseline diff. Order is correct.
- SARIF export uses `write_sarif(report, args.xs)` when `args.xs` is set.

---

## 3. Burp extension vs CLI alignment

### 3.1 Option mapping

| Burp UI | CLI flag | Engine / daemon |
|--------|---------|------------------|
| Extended (-e) | `-e` | `extended` |
| Offensive (-O) | `-O` | `offensive` |
| Force (-f) | `-f` | **Not in engine** (see 2.2) |
| CVE (--cve) | `--cve` | Post-run `possible_cves` |
| CVE lookup (NVD) | `--cve-lookup` | `cve_lookup` in `run()` |
| Max files / size / per-type | `--max-files` etc. | Passed to `run()` |
| Baseline | `--baseline` | Post-run diff in CLI; daemon request can carry path |

Burp builds the CLI argument list correctly (including `-f`). The only mismatch is that the engine does not yet use `force`.

### 3.2 Daemon mode

- Burp can use **Use daemon** and POST to `/scan` with JSON body (extended, offensive, limits, etc.). Daemon calls `engine.run()` with the same semantics. No discrepancy found.

### 3.3 Version display

- Extension: version from `UnveilTab.class.getPackage().getImplementationVersion()` (JAR manifest), fallback `"?"`.
- Build sets `Implementation-Version` in the JAR. CLI version is shown in the extension after a successful version probe (`fetchUnveilVersion`). Consistent.

---

## 4. Summary and checklist

### Burp tab not appearing — fixes in code

- [x] Register suite tab **before** applying theme.
- [x] Make theme application optional (try/catch, log only).
- [x] On any construction failure, show an error panel as the Unveil tab and log full stack trace.
- [x] Defer proxy detection so it cannot break tab construction.
- [x] Log full stack trace to Burp extension errors for any failure.

### CLI

- [ ] **Optional:** Pass `args.f` (force) into `engine.run()` and implement force behavior in the engine, or document `-f` as reserved.
- [x] On baseline apply failure, log to stderr (was silent).

### Recommendations

1. **Immediate:** Reload the updated extension JAR and confirm the Unveil tab appears (full UI or error panel). If it’s the error panel, use the message and Extensions → Errors to fix the underlying issue (e.g. API version, missing class).
2. **If using very new Burp:** Consider aligning `montoya-api` in `build.gradle.kts` with your Burp version and re-testing.
3. **CLI:** Resolve or document the `-f`/force gap between CLI and engine when you touch that code path.
