# Changelog

## [Unreleased]

- (None.)

## [0.10.3] / [0.7.4] — 2026-02-14

- **CLI 0.10.3** — Senior audit P0–P3: findings export (CSV/MD, -xf), suggested order, confidence on chains, TLS/pinning hints, update_refs, credential_hints, db_summary, apk_manifest; Copy evidence, Copy launch command, ProcMon/fs_usage; force (-f) passed to engine (reserved); final bugfixes (dedup key, DB URI, fs_usage quoting).
- **Burp 0.7.4** — Export findings CSV/MD, Copy evidence, Suggested order in Summary, Confidence column, Update refs / Credential hints / DB summary / Import summary / Packed entropy / Non-HTTP refs tabs; TLS/Pinning filter; Copy launch command, Copy for ProcMon, Copy fs_usage one-liner; proxy note for non-HTTP.

## [0.10.2] / [0.7.3] — 2026-02-14

- **Burp 0.7.3** — Tab visibility: register tab first, keep Registration reference; fallback error panel; remove proxy reflection (exportProjectOptionsAsJson); View menu hint; audit doc.

## [0.10.2] / [0.7.2] — 2026-02-13

- **Thick client findings** — Dynamic findings from scan (Electron, Qt, .NET, certs, chains, gaps). **Payload library** — HackBar-style payloads tab in Burp (browse by category, copy payload).
- **Version bump** — CLI 0.10.2, Burp extension 0.7.2.

## [0.10.1] / [0.7.1] — 2026-02-13

- **Version bump** — CLI 0.10.1, Burp extension 0.7.1 (release).

## [0.10.0] — 2026-02-13

- **Recon depth** — Report: `import_summary` (unique libraries from analysis.imports), `packed_entropy` (high-entropy files), `non_http_refs` (ws://, wss://, port-only from extracted_refs). Electron: `main`, `preload`, `asar` from package.json. Attack graph: chains ordered by role (ANCHOR/BRIDGE/BLADE) then by matched_paths. Cert audit: `key_bits`, `algorithm` in parsed output. .NET: same-dir .exe.config/.dll.config parsed for Type.GetType, remoting, assemblyBinding → `config_hints` per finding. CVE lookup: prepend "Electron {version}" from `electron_info` when present. Chainability: `confidence` (high/medium/low/none) per row. Checklist: optional ±N lines context (UNVEIL_CHECKLIST_CONTEXT_LINES), `context` on findings.
- **CLI** — Version 0.10.0.

## [0.7.0] — unveil-burp — 2026-02-13

- **Summary** — Import summary, Packed/entropy, Non-HTTP refs lines. **Chainability** — Confidence column.
- **Build** — Version 0.7.0.

## [0.9.0] — 2026-02-13

- **P0–P2 Senior Tester Audit** — Interesting strings in report (URLs, IPs, paths, secret-like); ACL/permission audit (Windows icacls, macOS/Linux stat); .NET assembly name/version + dangerous API hints (dnfile/monodis/PowerShell); cert parsing (openssl, validity, self-signed, expired); CVE lookup (NVD API 2.0, optional `--cve-lookup` / NVD_API_KEY); bulk Import from Proxy for Live manipulation; instrumentation hints per surface; custom checklist patterns (UNVEIL_CHECKLIST_EXTRA) + severity (credential/dangerous_config/informational); paths to watch for process monitor correlation (ProcMon/fs_usage). Remaining work documented in `docs/REMAINING_ISSUES.md`.
- **CLI** — Version 0.9.0. New flags: `--cve-lookup`. Daemon: `cve_lookup` in scan request.
- **Report** — New keys: `interesting_strings`, `permission_findings`, `cert_findings`, `dotnet_findings`, `cve_lookup`, `instrumentation_hints`, `paths_to_watch`, `paths_to_watch_note`. Checklist findings include `severity`.

## [0.6.0] — unveil-burp — 2026-02-13

- **New tabs** — Interesting strings, Permission findings, Cert findings, Dotnet findings, CVE lookup, Instrumentation hints, Paths to watch. Checklist: Severity column. Summary: lines for all new sections.
- **Options** — CVE lookup (NVD) checkbox; persisted. **Bulk import from Proxy** — Import last N requests (optional host filter) into Live slots.
- **Build** — Version 0.6.0. Bulk import fix (proxy history type).

## [0.8.4] — 2026-02-13

- **CLI** — Version 0.8.4 (pyproject.toml). Fallback version in cli.py/sarif_export.py aligned.
- **Burp extension 0.5.3** — CVE hunt queries moved into **Summary** tab (no separate Possible CVEs tab); resizable split between summary text and CVE list. Chainability: filter (File/Ref), In-scope dropdown, row summary, tooltips, colored In scope column, context menu (Copy path/ref, Open ref as URL, Open file). Fix duplicate menu variable.

## [0.5.3] — unveil-burp — 2026-02-13

- CVE hunt queries in Summary tab (split pane); Possible CVEs tab removed. Chainability: filters, summary label, tooltips, In scope coloring, context menu (Copy, Open URL/file).

## [0.8.1] — 2026-02-13

- Version bump. Burp extension 0.4.1: rebuild JAR and **reload the extension** in Burp to see current UI (no Hunt plan tab; Attack graph is visual; Discovered HTML has View in panel). **Unveil CLI:** label in the tab shows the CLI version from `unveil --version`.

## [0.4.1] — unveil-burp — 2026-02-13

- Version bump. Rebuild with `./gradlew jar` and reload the extension in Burp to get the updated UI (Hunt plan tab removed; Attack graph visualization; View in panel for HTML).

## [0.8.0] — 2026-02-13

- **Attack graph** — Report includes `attack_graph` (chains + sendable_urls; chains include matched_paths from scan). Burp: Attack graph tab is a **visual graph** (role → surface → targets); **Send selected to Repeater** for one-click Repeater tabs per URL. Hunt plan tab removed (redundant with attack graph).
- **Discovered HTML in Burp** — **View in panel** renders selected HTML inside Burp (JEditorPane) so content displays without relying on system browser (avoids blank file://).

## [0.4.0] — unveil-burp (Burp Suite extension) — 2026-02-13

- **Attack graph tab** — Chains (missing role → surface → hunt targets → reason) and sendable URLs table. **Send selected to Repeater** creates a Repeater tab per http(s) URL.

## [0.7.0] — 2026-02-13

- **Extended mode (-e)** — Populates enum from plists (ATS/NSExceptionDomains) and helper/crashpad paths; reasoning layer can emit network_mitm and ipc_helper surfaces when data is present.
- **Single-file mode** — Uses full `build_reasoning()` so single-file runs get correct synth indicators, verdict, and findings.
- **BLADE hunt plan** — Missing-link suggestions for BLADE role (preload.js, ASAR write, code execution vectors).
- **Configurable limits** — CLI `--max-files`, `--max-size-mb`, `--max-per-type`; env `UNVEIL_MAX_FILES`, `UNVEIL_MAX_SIZE_MB`, etc. Optional `-V`/`--verbose` and `UNVEIL_LOG=1` for structured JSON log to stderr.
- **PE manifest** — Embedded application manifest extraction (requestedExecutionLevel) from PE resources.
- **Electron info** — Report includes `electron_info` (version, nodeIntegration, contextIsolation, sandbox) from package.json.
- **Plist ref extraction** — URL schemes, bundle IDs, path-like refs from plists; plist included in reference extraction.
- **Chainability** — Report includes `chainability` (file → ref → in_scope / matched_type) linking extracted refs to discovered assets.
- **.env ref extraction** — New asset type `env` and path/URL extraction from .env files.
- **Linux persistence** — Harvest and tag systemd (.service, .timer), cron, autostart (.desktop); ANCHOR surface and exploit family.
- **JAR/WAR** — Target .jar or .war: unpack, report manifest, discovered assets and refs from archive; jar_archive surface and hunt intel.
- **Go / Rust / PyInstaller** — Classifier tags `go_binary`, `rust_binary`, `pyinstaller_binary` from file type for CVE/recon.
- **SARIF export** — `-xs FILE` exports SARIF 2.1 for CI (e.g. GitHub Code Scanning, VS Code SARIF viewer).
- **Diff / baseline** — `--baseline FILE` adds diff (added/removed findings, verdict_changed) and `baseline_suppressed` on findings.
- **Daemon scan API** — `POST /scan` with JSON body (target, extended, offensive, limits); returns full report.
- **Performance** — Lief used for Mach-O/ELF imports when available; per-run analysis cache; cache cleared at start of each run.
- **Tests** — Optional `pytest` tests for classifier and engine (normalize_surfaces, build_reasoning, extended enum).
- **Optional CVE** — `--cve` adds `possible_cves` (hunt_queries from verdict) to report.
- **Checklist scan** — Report includes `checklist_findings` (potential secrets/static-analysis no-nos in config, json, env, script); SARIF export includes checklist results.
- **Dedupe** — Discovered assets and extracted refs are deduped (one path per type; one entry per file with merged refs).

## [0.3.0] — unveil-burp (Burp Suite extension)

- **Checklist tab** — Displays `checklist_findings` (file, pattern, snippet, line).
- **Target / Site Map** — Scan results added as Burp audit issues (summary + up to 30 checklist findings) so they appear in Target and Dashboard.
- **UI dedupe** — Discovered assets and extracted refs tables dedupe by (path, type) and (file, refs) when populating from report.

## [0.2.0] — unveil-burp (Burp Suite extension)

- Full Unveil CLI options in UI: Path, Extended (-e), Offensive (-O), Force (-f), optional unveil executable path with Browse.
- Results: Summary, Attack graph (visual), Discovered HTML (view in panel), Raw JSON; Copy JSON, Save JSON, Save compact JSON, Export HTML.
- Rescan last target; guard empty report on save/copy; single-author project.

---

## [0.6.0] — CLI

- **Mobile (APK / IPA)** — Unpack and scan; native libs (APK) or `.app` bundles (IPA).
- **Windows persistence pack** — Run/Services, Scheduled Tasks, Startup, Winlogon, Scripts; harvest and tag `.xml`, `.vbs`, `.bat`, `.ps1`, `.cmd`.
- **.NET pack** — Detect CLR assemblies (PE); deserialization, remoting, assembly-load surfaces (ANCHOR).
- **Windows binary harvest** — `.dll` in scope; when no `.app` bundles, harvest `.exe`/`.dll` from directory tree.
- **Docs** — Full usage section on README; step-by-step commands in README and `docs/USAGE.md`.
- **Tagline** — "Opaque binaries in. Attack surfaces out."

## [0.5.0]

- DMG support (mount and scan).
- Electron, Qt, macOS persistence packs.
- Nmap-style summary; banner and plist noise filter.
- Rename unv → unveil; single CLI.
