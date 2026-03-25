<img width="600" height="376" alt="image" src="https://github.com/user-attachments/assets/7b4f0b20-d5f2-45f6-a0eb-18fb95bb653f" />

[![Release](https://img.shields.io/github/v/release/Pa7ch3s/Unveil?include_prereleases&label=release)](https://github.com/Pa7ch3s/Unveil/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://github.com/Pa7ch3s/Unveil)

---
**Hidden complexity in. Priorities out.**
---
> **Disclaimer:** This tool is for educational purposes and authorized security testing only. Unauthorized use against systems without prior written consent is strictly prohibited. The author accepts no liability for misuse or damage.
---
**Unveil** is built for packaged software: installers, thick clients, mobile bundles, hybrid stacks (Electron, Qt, .NET, and the rest). It pulls apart what is usually opaque and hands you a **short list of what to verify first**: where trust breaks, what persists, what connects to what, and what is actually worth a tester’s time. **Exploit viability over noise**, not another raw dump.

> * File identification and metadata extraction
> * Cryptographic hashing (MD5 / SHA1 / SHA256)
> * Import and symbol inspection
> * Entropy analysis (packed / protected detection)
> * String harvesting
> * Manifest parsing (APK permissions/components, *optional*; native scan included)
> * Structured, JSON-first output

---

**Under the hood:** execution surfaces, trust boundaries, persistence anchors, and lateral bridges. The output is mapped so you are not guessing where the story falls apart.

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

**More:** [Features & version history](docs/FEATURES.md) · [Vulnerability mapping](docs/VULNERABILITY_MAPPING.md) · [Getting started](docs/GETTING_STARTED.md) · [Glossary](docs/GLOSSARY.md)


---

## Install

**Requirements:** CLI: Python 3.9+, macOS/Linux/Windows. DMG scan: macOS only. Burp extension: Java 17+, Burp Suite 2023.8+. Optional: [lief](https://github.com/lief-project/LIEF) for faster Mach-O/ELF parsing.

**CLI (recommended):**

```bash
pipx install git+https://github.com/Pa7ch3s/Unveil.git
```

**Burp Suite extension:** Add an **Unveil** tab inside Burp. **How to install:** (1) Download `unveil-burp-0.7.6.jar` from [Releases](https://github.com/Pa7ch3s/Unveil/releases), or build from source: `cd unveil-burp && ./gradlew jar`. (2) In Burp: **Extensions** → **Installed** → **Add** → **Extension type: Java** → select the JAR. (3) The **Unveil** tab appears in the main tab bar (if not visible, use **View** menu → **Unveil** or **Restore default tab layout**). See **[unveil-burp/](unveil-burp/)** for details.

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

3. Use a new terminal window, or run `unv` then Tab again. Only `unveil` (and any other `unv*` tools you have) should appear.

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
Displays the installed version (e.g. `Unveil RADAR v0.10.8`).

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
