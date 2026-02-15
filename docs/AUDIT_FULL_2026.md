# Full audit — CLI, Burp extension, GitHub (2026-02)

**Scope:** No bugs, no duplicate code, no miswrites. Single source of truth for versions.

---

## 1. Version alignment (current)

| Component | Source of truth | Current value |
|-----------|-----------------|---------------|
| **CLI** | `pyproject.toml` → `version` | **0.10.2** |
| **CLI fallback** | `unveil/cli.py`, `unveil/sarif_export.py` | `"0.10.2"` (must match pyproject) |
| **Burp extension** | `unveil-burp/build.gradle.kts` → `version` | **0.7.3** |
| **Burp JAR** | Built from Gradle → `unveil-burp-{version}.jar` | `unveil-burp-0.7.3.jar` |
| **README / CHANGELOG** | Features and release notes | CLI 0.10.2, Burp 0.7.3 |

**Verified:** pyproject.toml 0.10.2; build.gradle.kts 0.7.3; cli.py and sarif_export.py fallback 0.10.2; README Features "CLI 0.10.2, Burp 0.7.3"; CHANGELOG [0.10.2]/[0.7.3] as latest release.

---

## 2. CLI audit

### 2.1 Entry points and version

- **Entry:** `unveil.cli:main` (pyproject.toml `[project.scripts]`). `unveil --version` prints `Unveil RADAR v{VERSION}`; VERSION from `importlib.metadata.version("unveil")` with fallback `"0.10.2"`.
- **SARIF:** `unveil/sarif_export.py` uses `_UNVEIL_VERSION` from metadata, fallback `"0.10.2"`. Single duplication of fallback string (acceptable; both must match pyproject).

### 2.2 Bugs fixed in this audit

- **Baseline apply:** Previously `except Exception: pass` swallowed errors. Now logs to stderr: `Unveil: baseline apply failed: {e}`.

### 2.3 Known gap (no bug)

- **`-f` (force):** CLI accepts `-f` and Burp passes it to the CLI. `engine.run()` has no `force` parameter, so the engine does not use it. CLI and daemon do not pass `force` to the engine. Documented in AUDIT_CLI_AND_BURP.md as optional follow-up.

### 2.4 No duplicate logic

- Single `run()` call from cli.py; daemon calls same `engine.run()`. Version read from metadata in two places (cli, sarif_export) with same fallback — intentional for independent modules.

### 2.5 Error handling

- Scan: exceptions caught, message to stderr, exit 1; with `-V` re-raise.
- Report error (metadata.error): exit 1 after optional pretty print.
- Baseline: now logs on apply failure.
- Exports (-xh, -xj, -xx, -xs): no try/except; failures propagate (acceptable for CLI).

---

## 3. Burp extension audit

### 3.1 Entry and loading

- **Service loader:** `META-INF/services/burp.api.montoya.BurpExtension` → `burp.UnveilExtension`. Present in repo and JAR.
- **Manifest:** Implementation-Version, Burp-Extension-Name, Burp-Extension-Expected-API-Version 2023.8. Extension version from `UnveilTab.class.getPackage().getImplementationVersion()` (JAR manifest), fallback `"?"`.

### 3.2 Duplicate code removed in this audit

- **buildUnveilArgs / exportSarif:** SARIF export previously built its own CLI args (duplicate of options -e, -O, -f, --cve, --cve-lookup) and omitted --max-files, --max-size-mb, --max-per-type, --baseline. Now `exportSarif()` uses `buildUnveilArgs(target, null, null, outPath)`.
- **Change:** Added 4-arg overload `buildUnveilArgs(target, jsonPath, htmlPath, sarifPath)`; 3-arg overload delegates to it with `sarifPath = null`. All CLI invocations (scan, export HTML, export SARIF) use the same builder so options and limits stay consistent.

### 3.3 No proxy reflection

- `detectProxyListener()` no longer uses reflection; returns default `"127.0.0.1:8080"`. No internal Burp API calls.

### 3.4 Tab registration

- Registration kept in field `suiteTabRegistration` so the tab is not dropped. Tab registered before `applyThemeToComponent`; theme application wrapped in try/catch. Fallback error panel on construction failure.

### 3.5 No other duplicate code

- Single `extensionVersion()`; single `resolveUnveilPath()`; single `buildUnveilArgs` for all process builds.

---

## 4. GitHub / docs audit

### 4.1 README (root)

- **Features:** v0.10.2 and v0.7.3 (Burp) bullets; "CLI 0.10.2, Burp 0.7.3" in first feature line.
- **Install:** CLI (`pipx install git+https://github.com/Pa7ch3s/Unveil.git`); Burp (download 0.7.3 JAR or build, load in Extensions, View menu hint).
- **Version example:** `Unveil RADAR v0.10.2` in Version and help section.
- **Links:** unveil-burp/ linked; Releases linked for JAR.

### 4.2 unveil-burp/README.md

- **How to install (Burp):** 4 steps (get JAR, load in Burp, open tab, optional CLI). JAR name `unveil-burp-0.7.3.jar`.
- **Build / Load in Burp:** JAR path 0.7.3; no duplicate or conflicting instructions.
- **What's in the tab / Implemented:** v0.7.3.

### 4.3 CHANGELOG.md

- **Current release:** [0.10.2] / [0.7.3] — 2026-02-14 (Burp tab visibility, proxy removal, etc.).
- **Historical:** [0.7.2], [0.10.0], etc. kept for history. No miswrites.

### 4.4 Other docs

- **docs/AUDIT_CLI_AND_BURP.md:** JAR path 0.7.3; baseline item marked done.
- **docs/USAGE.md:** Version example v0.10.2.
- **docs/AUDIT_TESTING_PHASES_AND_RECON_DEPTH.md:** Title and “reflects” line v0.10.2, Burp 0.7.3.

### 4.5 No miswrites

- No stray 0.7.2 or 0.10.0 in “current” context. 0.7.2 and 0.10.0 appear only in historical features or changelog entries.

---

## 5. Checklist summary

| Area | Status |
|------|--------|
| CLI version single source (pyproject) + fallbacks aligned | OK |
| Burp version 0.7.3 in build and docs | OK |
| CLI baseline apply: log on failure (no silent pass) | Fixed |
| Burp: no duplicate buildUnveilArgs; SARIF uses shared builder | Fixed |
| Burp: SARIF export gets limits/baseline/options | Fixed |
| No proxy reflection in Burp | OK |
| README / CHANGELOG / Burp README version and install | OK |
| Audit doc baseline item updated | OK |

---

## 6. Optional follow-ups (not bugs)

- **CLI `-f`:** Implement or document that engine does not yet use `force`.
- **Single version constant:** Could move fallback `"0.10.2"` to a shared constant (e.g. `unveil/version.py`) imported by cli and sarif_export; low priority while both match pyproject.
