# Features (version history & capabilities)

* **v0.10.8 / Burp 0.7.6** — **Windows plug-and-play:** Scanner uses **LIEF** and in-process string extraction (no `strings.exe` or other external tools), so the daemon runs reliably on Windows without PATH hacks. Burp extension auto-starts the daemon from `%LOCALAPPDATA%\Unveil\` when you load the JAR; install.ps1 places the no-console exe there. One-click Scan, no terminal.
* **v0.10.7** — CLI and release tag aligned; plug-and-play Windows zip + daemon exe.
* **v0.10.4** — CLI 0.10.4, Burp 0.7.5. Consolidated Findings and Summary tabs with type dropdown; custom strings filter in Interesting strings.
* **v0.7.5** (Burp) — Single Findings tab (Thick client / Permission / Cert / Dotnet / CVE) and Summary tab (Main / DB / Import / Packed) with dropdowns; custom strings filter.
* **v0.10.1** — Version bump (CLI 0.10.1, Burp 0.7.1).
* **v0.10.0** — Recon depth: import summary (unique libraries), packed/entropy list, non-HTTP refs (ws://, port); Electron preload/asar from package.json; attack graph chain order (role + matched_paths); cert key_bits/algorithm; .NET config hints (Type.GetType, remoting); CVE lookup uses Electron version; checklist ±context lines; Burp Summary (import/packed/non-HTTP) and Chainability confidence column.
* **v0.9.0** — P0–P2 audit complete: interesting strings, ACL/permission audit, .NET assembly + dangerous API hints, cert parsing, CVE lookup (NVD), bulk Import from Proxy; instrumentation hints, custom checklist + severity, paths to watch; Burp tabs for all. CVE hunt queries in Summary (Burp); Chainability filters and context menu.
* **v0.8.0** — Attack graph (chains + sendable_urls); Burp: Attack graph tab and **Send selected to Repeater**.
* **v0.7.0** — Extended mode (-e) populates ATS/helpers for deeper surfaces; single-file gets full reasoning; BLADE hunt plan; configurable limits (CLI/env) and verbose logging; PE manifest extraction; Electron version/hardening in report; plist + .env ref extraction; chainability section (refs → discovered assets); **checklist scan** (potential secrets/static-analysis no-nos in config, json, env, script → `checklist_findings`); **dedupe** of discovered_assets and extracted_refs; Linux persistence (systemd, cron, autostart); JAR/WAR scan; Go/Rust/PyInstaller tags; SARIF export (-xs); diff/baseline (--baseline); daemon `POST /scan`; lief + per-run cache; tests; `--cve` for possible_cves.

* **Mobile (APK / IPA)** — Point at an `.apk` or `.ipa`; Unveil unpacks it, then runs the full radar on native libs (APK) or `.app` bundles (IPA).
* **DMG support** — Pass a `.dmg` path; Unveil mounts it, discovers `.app` bundles, runs the full pipeline, then unmounts.
* **Electron pack** — Preload/ASAR write surfaces, helper/IPC/crashpad bridges, ANCHOR/BRIDGE classification.
* **Qt pack** — Qt plugin rpath hijack (ANCHOR), qt.conf and plugin path detection.
* **macOS persistence pack** — LaunchAgents, LaunchDaemons, Login Items, XPC; plists in those paths are harvested and tagged.
* **Windows persistence pack** — Run/RunOnce, Services, Scheduled Tasks, Startup, Winlogon, Scripts; `.xml`, `.vbs`, `.bat`, `.ps1`, `.cmd` in those paths are harvested and tagged (ANCHOR).
* **.NET pack** — PE files with a CLR (COM descriptor) directory are tagged as managed assemblies; deserialization, remoting, assembly-load surfaces with CWE/CVE-style intel (ANCHOR).
* **Nmap-style summary** — Target, exploitability band, killchain roles, frameworks, and surface counts before the full JSON.
* **Discovered assets** — Configs, scripts, certs, manifests, and data files by type (html, xml, json, config, script, plist, manifest, policy, cert, data) for recon and chainability.
* **Reference extraction** — Lightweight parsing of XML, JSON, and .config files to extract paths and URLs for trust-boundary and chain mapping.
* **Attack graph** — Report includes `attack_graph`: chains (missing role → surface → hunt targets, with matched_paths from scan) and sendable_urls (http(s) from refs/hunt plan). Burp: Attack graph tab shows a **visual graph**; **Send selected to Repeater** for one-click Repeater tabs. Discovered HTML: **View in panel** renders HTML inside Burp.

**Professional use:** Unveil's recon and surface model aligns with thick-client security testing (e.g. [OWASP](https://owasp.org/) thick-client and desktop app guidance). Use the report's `discovered_assets`, `extracted_refs`, `attack_graph`, and hunt plan for structured pentest workflows.
