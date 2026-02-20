<img width="600" height="376" alt="image" src="https://github.com/user-attachments/assets/7b4f0b20-d5f2-45f6-a0eb-18fb95bb653f" />

[![Release](https://img.shields.io/github/v/release/Pa7ch3s/Unveil?include_prereleases&label=release)](https://github.com/Pa7ch3s/Unveil/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://github.com/Pa7ch3s/Unveil)

---
**Opaque binaries in. Attack surfaces out.**
---
> **Disclaimer:** This tool is for educational purposes and authorized security testing only. Unauthorized use against systems without prior written consent is strictly prohibited. The author accepts no liability for misuse or damage.
---
Focuses on **exploit viability**, not just indicators.

> * File identification and metadata extraction
> * Cryptographic hashing (MD5 / SHA1 / SHA256)
> * Import and symbol inspection
> * Entropy analysis (packed / protected detection)
> * String harvesting
> * Manifest parsing (APK permissions/components — *optional*, native scan included)
> * Structured, JSON-first output

---

Models: execution surfaces, trust boundaries, persistence anchors, and lateral bridges

---

## Supported formats

| Format | Status |
|--------|--------|
| **DMG** (macOS disk images) | ✅ Mounted and scanned; full radar on contents |
| **Mach-O** (macOS binaries, `.app` bundles) | ✅ |
| **Windows PE** (.exe / .dll) | ✅ |
| **ELF** (Linux) | ✅ |
| **Electron / ASAR** (app.asar, preload, helpers) | ✅ |
| **Qt** (plugins, rpath, qt.conf) | ✅ |
| **macOS persistence** (LaunchAgents, LaunchDaemons, XPC, plists) | ✅ |
| **Windows persistence** (Run/Services, Scheduled Tasks, Startup, Winlogon, Scripts) | ✅ Directory scan for .xml, .vbs, .bat, .ps1, .cmd in those paths |
| **.NET / CLR** (managed assemblies) | ✅ PE with CLR descriptor detected; deserialization, remoting, assembly-load surfaces (ANCHOR) |
| **APK** (Android) | ✅ Unpacked; native `lib/*.so` harvested and analyzed (ELF) |
| **IPA** (iOS) | ✅ Unpacked; `Payload/*.app` scanned like macOS bundles (Mach-O, plists) |
| **JAR / WAR** (Java) | ✅ Unpacked; META-INF/manifest, discovered assets and refs; jar_archive surface |
| **Linux persistence** (systemd, cron, autostart) | ✅ .service, .timer, .desktop in known paths harvested and tagged (ANCHOR) |

---

## Features (v0.10.4)

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
* **.NET pack** — PE files with a CLR (COM descriptor) directory are tagged as managed assemblies; deserialization, remoting, and assembly-load surfaces with CWE/CVE-style intel (ANCHOR).
* **Nmap-style summary** — Target, exploitability band, killchain roles, frameworks, and surface counts before the full JSON.
* **Discovered assets** — Configs, scripts, certs, manifests, and data files by type (html, xml, json, config, script, plist, manifest, policy, cert, data) for recon and chainability.
* **Reference extraction** — Lightweight parsing of XML, JSON, and .config files to extract paths and URLs for trust-boundary and chain mapping.
* **Attack graph** — Report includes `attack_graph`: chains (missing role → surface → hunt targets, with matched_paths from scan) and sendable_urls (http(s) from refs/hunt plan). Burp: Attack graph tab shows a **visual graph**; **Send selected to Repeater** for one-click Repeater tabs. Discovered HTML: **View in panel** renders HTML inside Burp.

**Professional use:** Unveil’s recon and surface model aligns with thick-client security testing (e.g. [OWASP](https://owasp.org/) thick-client and desktop app guidance). Use the report’s `discovered_assets`, `extracted_refs`, `attack_graph`, and hunt plan for structured pentest workflows.

---

## Vulnerability mapping

Unveil helps discover and prioritize thick-client flaws that manual testers would otherwise hunt with multiple tools. The table below maps **common vulnerability types** to what Unveil surfaces so you know where to focus.

| Thick-client flaw | What Unveil surfaces |
|-------------------|----------------------|
| **DLL / library hijacking** | Qt plugin dir and `@rpath` (ANCHOR); writable plugin paths, `qt.conf`; Windows `.exe`/`.dll` harvest and load paths from refs. |
| **Insecure storage / secrets** | **Checklist** scan: hardcoded keys, JWT, Slack/GitHub tokens, PEM, disabled SSL in config/json/env/script; discovered assets by type. |
| **Preload / ASAR hijack (Electron)** | Preload path, ASAR write, and helper surfaces (ANCHOR/BRIDGE); attack graph chains and matched paths; CVE hunt queries for Electron. |
| **Persistence abuse** | Windows: Run/RunOnce, Services, Scheduled Tasks, Startup, Winlogon, Scripts (ANCHOR). macOS: LaunchAgents, LaunchDaemons, XPC. Linux: systemd, cron, autostart. |
| **.NET deserialization / assembly load** | CLR assemblies tagged (ANCHOR); deserialization, remoting, assembly-load surfaces with CWE/CVE-style intel. |
| **Network / TLS (MITM)** | Refs and URLs in config; ATS/plist exceptions; **Send to Repeater** in Burp for http(s) endpoints; checklist flags disabled cert validation. |
| **Trust boundary / chainability** | `chainability` (file → ref → in scope); `extracted_refs`; attack graph with missing roles and suggested surfaces. |

Use the report’s **attack graph**, **checklist_findings**, and **discovered_assets** as the recon foundation; then follow up with manual testing (e.g. proxy, Frida, or permission checks) where the tool highlights risk. For direction and future ideas (test-case mapping, instrumentation, permission auditing), see **[docs/VISION.md](docs/VISION.md)**. For **gaps and improvements** for new testers, see **[docs/GAPS_AND_IMPROVEMENTS.md](docs/GAPS_AND_IMPROVEMENTS.md)**. For a **senior tester / SME audit** (what is missing for advanced static and dynamic thick-client testing), see **[docs/SENIOR_TESTER_AUDIT.md](docs/SENIOR_TESTER_AUDIT.md)**.

---

## Getting started

**One install: CLI + Burp extension**

**Windows — plug and play (no Python/pip):** Download [unveil-burp-plug-and-play-windows.zip](https://github.com/Pa7ch3s/Unveil/releases) from the latest release. Unzip, load the JAR in Burp, run `unveil-daemon.exe`, and in the Unveil tab keep **Use daemon** checked. Then Scan. No install steps.

**From source (all platforms):**

1. **Clone the repo** (for both CLI and Burp extension): `git clone https://github.com/Pa7ch3s/Unveil.git && cd Unveil`
2. **Install the CLI** (required for terminal scans; optional if you only use Burp + daemon): `pipx install .` — or from PyPI: `pipx install unveil-radar`. Run `unveil -h` to confirm.
3. **Install the Burp extension:** `cd unveil-burp && ./gradlew jar` — JAR: `unveil-burp/build/libs/unveil-burp-0.7.5.jar`. In Burp Suite (2023.8+): **Extensions** → **Installed** → **Add** → **Extension type: Java** → select that JAR. The **Unveil** tab appears.
4. **Run a first scan:** **CLI:** `unveil -C /path/to/your/app` (e.g. `.app` or directory; richer: `unveil -C /path/to/app -e -O`). **Burp:** In the Unveil tab, set **Path** (or **Browse…**), click **Scan**. If you see "unveil not found", set **Unveil executable (optional)** to the path from `which unveil`, or enable **Use daemon** and start with `unveil` or `python -m unveil.daemon`.
5. **Read the output:** Banner → Nmap-style summary → full JSON. In Burp: **Summary**, **Attack graph** (**Send selected to Repeater** for URLs), **Checklist**, **Discovered assets**, **Chainability**.


**Report at a glance:** **Summary** = high-level verdict and counts; **Attack graph** = what to hunt (missing role → surface → targets); **Checklist** = potential secrets and config risks (with severity); **Discovered assets** = files by type; **Chainability** = which file references which path/URL; **Instrumentation hints** = per-surface hook/Frida suggestions; **Paths to watch** = paths for process monitor correlation.

**Process monitor correlation (P2):** The report includes `paths_to_watch` (install dir, binaries, config paths). In Burp, use the **Paths to watch** tab and **Copy all paths**; then run **ProcMon** (Windows) or **fs_usage** (macOS) filtered to those paths to see what the app actually touches at runtime and correlate with static findings.

**Custom checklist patterns:** Set `UNVEIL_CHECKLIST_EXTRA` to the path of a JSON file. Each entry: `{"pattern_name": "...", "regex": "...", "severity": "credential"|"dangerous_config"|"informational"}`. Built-in patterns have severity (credential, dangerous_config, informational) for prioritization.

---

## Glossary

| Term | Meaning |
|------|---------|
| **ANCHOR** | Persistence / foothold — a way to run again or influence what the app loads (e.g. Qt plugin dir, Windows Run key, Electron preload). |
| **BRIDGE** | Lateral movement — moving between processes or privilege (e.g. helper processes, network, IPC). |
| **BLADE** | Code execution — running attacker-controlled code in the app (e.g. renderer, main process). |
| **Exploitability band** | Summary risk level derived from surfaces and missing roles. |
| **Chainability** | File → ref links: which discovered file references which path or URL (for trust boundaries and “what loads what”). |
| **Attack graph** | Chains of “missing role → vulnerable component → hunt targets” with matched paths from the scan; plus sendable http(s) URLs. |

Unveil models a simple kill chain: get a foothold (ANCHOR), move laterally (BRIDGE), achieve code execution (BLADE). The report highlights what’s present and what’s missing so you know where to test next.

---

## Install

**Requirements:** CLI: Python 3.9+, macOS/Linux/Windows. DMG scan: macOS only. Burp extension: Java 17+, Burp Suite 2023.8+. Optional: [lief](https://github.com/lief-project/LIEF) for faster Mach-O/ELF parsing.

**CLI (recommended):**

```bash
pipx install git+https://github.com/Pa7ch3s/Unveil.git
```

**Burp Suite extension:** Add an **Unveil** tab inside Burp. **How to install:** (1) Download `unveil-burp-0.7.5.jar` from [Releases](https://github.com/Pa7ch3s/Unveil/releases), or build from source: `cd unveil-burp && ./gradlew jar`. (2) In Burp: **Extensions** → **Installed** → **Add** → **Extension type: Java** → select the JAR. (3) The **Unveil** tab appears in the main tab bar (if not visible, use **View** menu → **Unveil** or **Restore default tab layout**). See **[unveil-burp/](unveil-burp/)** for details.

**Upgrading from `unv`:** The CLI was renamed to `unveil`. If you still see `unv` or `unv-daemon` when you tab-complete:

1. Find and remove the old executables (pipx uses `~/.local/bin`; a user Python install often uses `~/Library/Python/3.9/bin` on macOS):

```bash
which unv unv-daemon
rm -f ~/.local/bin/unv ~/.local/bin/unv-daemon
rm -f ~/Library/Python/3.9/bin/unv ~/Library/Python/3.9/bin/unv-daemon
```

2. Clear your shell’s command cache so tab-completion updates:

```bash
hash -r
```

3. Use a new terminal window, or run `unv` then Tab again — only `unveil` (and any other `unv*` tools you have) should appear.

---

Verify/display version and flags:

```bash
unveil --version
unveil -h
```
<img width="800" height="554" alt="image" src="https://github.com/user-attachments/assets/9cbd824f-a3b6-49ee-b782-aeee6faa208b" />

---

## Usage

Step-by-step commands with full syntax. Add screenshots where applicable.

### Version and help

```bash
unveil --version
```
Displays the installed version (e.g. `Unveil RADAR v0.10.4`).

```bash
unveil -h
```
Lists all flags: `-C` (target), `-e`, `-O`, `-f`, `-q`, `-xh`, `-xj`, `-xx`.

---

### Basic scan

```bash
unveil -C /path/to/target
```
- **Target:** Directory or `.app` bundle.
- **Output:** Banner, Nmap-style summary (target, exploitability, killchain roles, frameworks, surface counts), then full JSON to stdout.

**Examples:**

```bash
unveil -C /Applications/Safari.app
unveil -C "C:\Program Files\MyApp"
```

---

### Scan a single file

```bash
unveil -C /path/to/file.exe
```
Single file (e.g. `.exe`, `.dll`, `.so`, `.dylib`, `.js`). Output is JSON for that file only.

```bash
unveil -C ./suspicious.exe
unveil -C /usr/lib/libfoo.so
```

---

### Scan a DMG (macOS disk image)

```bash
unveil -C /path/to/image.dmg
```
Mounts the DMG, discovers `.app` bundles inside, runs the full radar, then unmounts.

---

### Scan an IPA (iOS app)

```bash
unveil -C /path/to/app.ipa
```
Unpacks the IPA, scans `Payload/*.app` like macOS bundles (Mach-O, plists), then cleans up.

---

### Scan an APK (Android app)

```bash
unveil -C /path/to/app.apk
```
Unpacks the APK, harvests and analyzes `lib/*/*.so` (ELF), then cleans up.

---

### Quiet mode

```bash
unveil -C /path/to/target -q
```
Suppresses the banner and human-readable summary; only raw JSON. Useful for piping or CI.

---

### Extended surface expansion

```bash
unveil -C /path/to/target -e
```
Enables deeper persistence and lateral surface expansion in the reasoning layer.

---

### Offensive surface synthesis

```bash
unveil -C /path/to/target -O
```
Enables exploit-chain modeling (offensive surface synthesis) in the report.

---

### Force unsigned / malformed binaries

```bash
unveil -C /path/to/target -f
```
Attempts analysis even when binaries are unsigned or malformed.

---

### Export to HTML

```bash
unveil -C /path/to/target -xh report.html
```
Writes a pretty-rendered HTML report to `report.html`. The report lists **discovered .html/.htm** files inside the target with clickable `file://` links so you can open them in a browser for attacks, redev, or transparency. Sections are collapsible.

---

### Export to JSON (indented)

```bash
unveil -C /path/to/target -xj report.json
```
Writes the full indented JSON report to `report.json`.

---

### Export to JSON (compact)

```bash
unveil -C /path/to/target -xx report.json
```
Writes the same report as single-line (compact) JSON.

---

### Quiet + export (CI / pipeline)

```bash
unveil -C /path/to/target -q -xj report.json
```
No banner, no summary; JSON is written to file. Good for scripts and CI.

```bash
unveil -C /path/to/target -q -xh report.html
```
Quiet run; only the HTML file is produced.

---

### Combined options

```bash
unveil -C /path/to/target -e -O -xj report.json
```
Extended expansion, offensive synthesis, and indented JSON export in one run.

---

### Flag reference

| Flag | Description |
|------|-------------|
| `-C`, `--target` | **Required.** Path to directory, .app, file, .dmg, .ipa, .apk, or .jar/.war. |
| `-e` | Extended surface expansion (ATS/helpers from plists and paths). |
| `-O` | Offensive surface synthesis (exploit-chain modeling). |
| `-f` | Force analysis of unsigned/malformed binaries (passed to engine; reserved for future use, e.g. skip signature checks). |
| `-q`, `--quiet` | Suppress banner and pretty summary. |
| `-V`, `--verbose` | Structured JSON log to stderr (or `UNVEIL_LOG=1`). |
| `--max-files N` | Max binaries to analyze (env: `UNVEIL_MAX_FILES`). |
| `--max-size-mb MB` | Max file size in MB (env: `UNVEIL_MAX_SIZE_MB`). |
| `--max-per-type N` | Max discovered assets per type (env: `UNVEIL_MAX_PER_TYPE`). |
| `-xh FILE` | Export HTML report to FILE. |
| `-xj FILE` | Export indented JSON report to FILE. |
| `-xx FILE` | Export compact JSON report to FILE. |
| `-xs FILE` | Export SARIF 2.1 report to FILE (for CI/IDE). |
| `--baseline FILE` | Baseline report JSON; add diff and baseline_suppressed. |
| `--cve` | Add `possible_cves` (hunt_queries) to report. |

> *All output is JSON. Designed to drop directly into pipelines, tooling, and reports.*

Extended usage (same content): **[docs/USAGE.md](docs/USAGE.md)**.

---

## Author

pa7ch3s

## License

MIT
