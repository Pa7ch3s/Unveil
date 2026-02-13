<img width="600" height="376" alt="image" src="https://github.com/user-attachments/assets/7b4f0b20-d5f2-45f6-a0eb-18fb95bb653f" />

[![Release](https://img.shields.io/github/v/release/Pa7ch3s/Unveil?include_prereleases&label=release)](https://github.com/Pa7ch3s/Unveil/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://github.com/Pa7ch3s/Unveil)

---
**Opaque binaries in. Attack surfaces out.**
---
> **Disclaimer:** This tool is for educational purposes and authorized security testing only. Unauthorized use against systems without prior written consent is strictly prohibited. The author accepts no liability for misuse or damage.
---
It focuses on **exploit viability**, not just indicators.

> * File identification and metadata extraction
> * Cryptographic hashing (MD5 / SHA1 / SHA256)
> * Import and symbol inspection
> * Entropy analysis (packed / protected detection)
> * String harvesting
> * Manifest parsing (APK permissions/components — *optional*, native scan included)
> * Structured, JSON-first output

---

"Models execution surfaces, trust boundaries, persistence anchors, and lateral bridges... then tells you what to hunt next."

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

---

## Features (v0.6.0)

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

**Professional use:** Unveil’s recon and surface model aligns with thick-client security testing (e.g. [OWASP](https://owasp.org/) thick-client and desktop app guidance). Use the report’s `discovered_assets`, `extracted_refs`, and hunt plan for structured pentest workflows.

---

## Install

**CLI (recommended):**

```bash
pipx install git+https://github.com/Pa7ch3s/Unveil.git
```

**Burp Suite extension:** Add an **Unveil** tab inside Burp — see **[unveil-burp/](unveil-burp/)** for build and load instructions.

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
Displays the installed version (e.g. `Unveil RADAR v0.6.0`).

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
| `-C`, `--target` | **Required.** Path to directory, .app, file, .dmg, .ipa, or .apk. |
| `-e` | Extended surface expansion. |
| `-O` | Offensive surface synthesis (exploit-chain modeling). |
| `-f` | Force analysis of unsigned/malformed binaries. |
| `-q`, `--quiet` | Suppress banner and pretty summary. |
| `-xh FILE` | Export HTML report to FILE. |
| `-xj FILE` | Export indented JSON report to FILE. |
| `-xx FILE` | Export compact JSON report to FILE. |

> *All output is JSON. Designed to drop directly into pipelines, tooling, and reports.*

Extended usage (same content): **[docs/USAGE.md](docs/USAGE.md)**.

---

## License

MIT
