# Feature expansion: where Unveil can grow

This doc outlines **additional functionality** that would make Unveil more robust and useful, grouped by theme. It builds on the audit and thick-client discovery doc.

---

## 1. Make existing modes actually do more

### 1.1 Extended mode (-e): populate `enum` for expand()

Right now `extended=True` only passes an empty `enum` into `expand()`. The expander already knows how to use:

- **`enum["helpers"]`** — for `electron_helper_ipc` (helper paths, process names).
- **`enum["ATS"]`** — for `ats_mitm_downgrade` (e.g. `NSExceptionDomains` from plists).

**Add:** When `-e` is set, in directory/bundle mode:

- Scan discovered plists (or a subset) for `NSExceptionDomains` / ATS keys and pass them as `enum["ATS"]`.
- From Electron bundles, collect paths to Helper.app / crashpad / helper executables and pass as `enum["helpers"]`.

That would let the reasoning layer emit **network_mitm** and **ipc_helper** surfaces when the data is there, instead of only when those tags come from the classifier.

### 1.2 Single-file mode: correct surface → synth path

Single-file runs pass the full classifier dict as `surface` into `synthesize()`, so synth indicators are always empty. **Fix:** Reuse `build_reasoning([entry], extended=..., offensive=...)` for single-file, or map `entry["class"]` to a list of surface records with string `surface` (e.g. from `surfaces`/`exploits`) before calling `synthesize()`. Then single-file reports get proper exploit families, CWE/CVE tags, and verdict.

### 1.3 BLADE in hunt plan

`missing_link_engine.MISSING_LINK_TEMPLATES` only has ANCHOR and BRIDGE. When the missing role is **BLADE**, the hunt plan is empty. **Add:** BLADE suggestions (e.g. “preload.js, renderer RCE, ASAR write, code execution vectors”) so the report tells the analyst what to look for to complete the chain.

---

## 2. More formats and runtimes

### 2.1 Java / JAR

- **Harvest:** `.jar`, `.war` (as ZIP); list classes and `META-INF/MANIFEST.MF`.
- **Surfaces:** Unsigned/signed JAR, `Main-Class`, `Class-Path`, JNLP-style refs; deserialization (e.g. `ObjectInputStream` in class path).
- **Asset:** Treat JAR as a pack; discovered assets inside (properties, XML, scripts).

Useful for thick clients that ship JARs or use Java Web Start / JNLP.

### 2.2 Python / PyInstaller / PyOxidizer

- **Detect:** PyInstaller payload, PyOxidizer, or embedded Python in a binary.
- **Surfaces:** Unpacked payloads, `*.pyc`, paths to scripts; potential code execution if payload is writable or loadable.

Extends coverage for Python-based desktop tools.

### 2.3 Go / Rust binaries

- **Detect:** Go (e.g. `runtime.main`, buildid) or Rust binaries via `file` or signatures.
- **Surfaces:** No dynamic imports (often static); still useful to tag “Go/Rust app” for CVE search and to feed entropy / packed detection. Optionally extract embedded config or version strings.

### 2.4 Linux persistence and scripts

- **systemd** user/system units (`.service`, `.timer`), **cron** (crontab, `/etc/cron.*`), **autostart** (`.desktop` in autostart dirs).
- **Harvest:** Same idea as Windows persistence — known paths and extensions; tag as persistence surfaces and list in discovered assets.

Brings “run on login/boot” coverage to Linux.

### 2.5 Containers / Flatpak / Snap

- **Flatpak:** Parse manifest (JSON/YAML); list refs and runtimes.
- **Snap:** Similar for snap metadata.
- **Generic container:** Optional “scan a rootfs path” to run the same harvest (binaries, persistence, assets) inside an image layer.

Useful when the thick client is shipped or run inside a container.

---

## 3. Deeper static analysis (no new formats)

### 3.1 Manifest parsing (implement the stub)

`static_parser.manifest()` is still a stub. **Implement for:**

- **APK:** AndroidManifest.xml — permissions, components, intent filters, debuggable, backup. Surfaces: exported components, cleartext traffic, etc.
- **PE:** Embedded application manifest (requestedExecutionLevel, dependencies). Surfaces: admin vs. asInvoker, compatibility.
- **JAR:** META-INF/MANIFEST.MF (when JAR support is added).

Feeds both “discovered” metadata and trust-boundary / permission hints.

### 3.2 Electron: version and hardening

- **Parse:** `package.json` (or equivalent) for Electron version, `nodeIntegration`, `contextIsolation`, `sandbox`, preload path.
- **Surfaces:** “Electron &lt; X” for known CVE bands; “nodeIntegration true” / “contextIsolation false” as high-value tags.
- **Report:** Add “electron_version” and “hardening” flags to the relevant findings so the report and CVE search are more precise.

### 3.3 .NET: assembly and deserialization hints

- **Today:** CLR detection only. **Add:** Assembly name, strong name, referenced assemblies (from metadata); optional heuristics for deserialization sinks (e.g. `BinaryFormatter`, `NetDataContractSerializer`, `Type.GetType` from config).
- **Surfaces:** “deserialization_sink”, “remoting”, “assembly_load_from_path”; link to CWE/CVE tags already in EXPLOIT_FAMILIES.

Makes the .NET pack more actionable for exploitability.

### 3.4 Plist: URL schemes, file associations, entitlements

- **Harvest:** All discovered plists (already in `discovered_assets`).
- **Parse (lightweight):** CFBundleURLTypes, CFBundleDocumentTypes, entitlements (e.g. keychain, app-sandbox).
- **Use:** Trust-boundary and chainability (e.g. “this app opens these URL schemes”); feed into ref extraction and hunt plan.

---

## 4. Reference extraction and chainability

You already have XML, JSON, and .config ref extraction and `extracted_refs` in the report. **Expand:**

- **Plist:** Paths, bundle IDs, URL schemes, script paths.
- **package.json:** Scripts, dependencies, main/preload paths.
- **INI / YAML:** Paths, URLs, script/config refs (with size caps).
- **.env / env files:** Paths and URLs in values.

Then (optionally) a **chainability section**: “File A references path/URL B; B is in discovered_assets or is a known surface type.” That directly supports “if I control X, what does Y load?”

---

## 5. Output, integration, and ops

### 5.1 SARIF export

- Emit **SARIF 2.1** (or latest) with results as “results”, surfaces as locations, verdict/exploitability as level/rule. Enables CI (e.g. GitHub Code Scanning, VS Code SARIF viewer) and standard tooling.

### 5.2 Diff / baseline

- **Diff:** Compare two reports (e.g. before/after patch) — new/removed surfaces, changed verdict.
- **Baseline:** Accept a baseline report and suppress or de-emphasize findings that match, so only new or changed items are highlighted.

Useful for regression and “did the fix reduce attack surface?”

### 5.3 Daemon: real scan API

- **Endpoint:** e.g. `POST /scan` with target path (or multipart upload), options (extended, offensive, force).
- **Return:** Full report JSON; optional query params to trigger HTML/JSON export to a path.
- **Use case:** Burp or other tools call the daemon instead of shelling to the CLI; same binary, remote or local.

### 5.4 Configurable limits and logging

- **CLI or env:** Override `MAX_FILES`, `MAX_SIZE`, `MAX_PER_TYPE`, `REF_EXTRACT_MAX_FILES` so large installs and CI can tune without code changes.
- **Logging:** Optional structured log (e.g. JSON lines) with levels; clear user-facing errors for DMG mount, unpack, and parse failures (as in the audit).

---

## 6. Performance and robustness

- **Single-walk asset collection** (audit 3.1): One tree walk that both harvests binaries and fills `discovered_assets` to avoid duplicate rglob.
- **Use lief for Mach-O/ELF:** You already have lief/pefile; use **lief** for import/segment parsing on Mach-O and ELF where available to reduce `otool`/`ldd` subprocess calls and improve speed.
- **Caching:** Per-run cache of `file` and imports by path so the same file is not re-analyzed if it appears in multiple contexts.
- **Tests:** Unit tests for classifier, `normalize_surfaces`, `build_reasoning`, and (optionally) a small fixture bundle for integration. Protects refactors and new flags (-e/-O).

---

## 7. Optional: CVE / version tie-in

EXPLOIT_FAMILIES already has `cve_search_tags`. **Optional step:**

- Detect framework/version (Electron, Qt, .NET runtime, etc.) from binaries or config.
- Query NVD (or a local CVE DB) by product/version or by keywords from `cve_search_tags`.
- Attach “possible_cves” or “hunt_queries” to the report so the analyst gets concrete CVE candidates without leaving the tool.

Can be behind a flag or a separate subcommand to avoid network dependency by default.

---

## Summary: high-impact, ordered by theme

| Theme | Features | Why it helps |
|-------|----------|---------------|
| **Use what you have** | Extended enum (ATS/helpers), single-file synth fix, BLADE hunt | Makes -e and single-file actually useful; complete hunt plan. |
| **Formats** | JAR, PyInstaller, Linux persistence, optional Flatpak/Snap | Broader coverage for thick clients and server-like installs. |
| **Static depth** | Manifest (APK/PE), Electron version/hardening, .NET sinks, plist URL schemes | More precise surfaces and CVE matching. |
| **Chainability** | Plist/package.json refs, chainability section | “What references what” and “what to tamper next.” |
| **Output/ops** | SARIF, diff/baseline, daemon scan API, limits/env, logging | Fits into CI, regression, and tooling. |
| **Performance** | Single walk, lief, cache, tests | Faster runs and safer changes. |

Implementing **1 (use what you have)** first gives the most payoff for the least new surface area; then **manifest + Electron + .NET depth** and **chainability** make the report more actionable; **formats** and **output/ops** expand who can use it and where (CI, other tools, more platforms).
