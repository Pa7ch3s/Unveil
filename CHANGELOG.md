# Changelog

## [Unreleased]

- (None.)

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

## [0.2.0] — unveil-burp (Burp Suite extension)

- Full Unveil CLI options in UI: Path, Extended (-e), Offensive (-O), Force (-f), optional unveil executable path with Browse.
- Results: Summary, Hunt plan (sortable table + filter), Raw JSON; Copy JSON, Save JSON, Save compact JSON, Export HTML.
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
