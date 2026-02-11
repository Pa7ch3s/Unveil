<img width="600" height="376" alt="image" src="https://github.com/user-attachments/assets/7b4f0b20-d5f2-45f6-a0eb-18fb95bb653f" />

## Unveil

Attack Path Discovery Engine

>*From binary to breach path.*
---
"Performs fast, local static triage on binaries, apps, and packages; turning opaque artifacts into structured, actionable intel."
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

## Recent features (v0.5.0)

* **Mobile (APK / IPA)** — Point at an `.apk` or `.ipa`; Unveil unpacks it, then runs the full radar on native libs (APK) or `.app` bundles (IPA).
* **DMG support** — Pass a `.dmg` path; Unveil mounts it, discovers `.app` bundles, runs the full pipeline, then unmounts.
* **Electron pack** — Preload/ASAR write surfaces, helper/IPC/crashpad bridges, ANCHOR/BRIDGE classification.
* **Qt pack** — Qt plugin rpath hijack (ANCHOR), qt.conf and plugin path detection.
* **macOS persistence pack** — LaunchAgents, LaunchDaemons, Login Items, XPC; plists in those paths are harvested and tagged.
* **Windows persistence pack** — Run/RunOnce, Services, Scheduled Tasks, Startup, Winlogon, Scripts; `.xml`, `.vbs`, `.bat`, `.ps1`, `.cmd` in those paths are harvested and tagged (ANCHOR).
* **.NET pack** — PE files with a CLR (COM descriptor) directory are tagged as managed assemblies; deserialization, remoting, and assembly-load surfaces with CWE/CVE-style intel (ANCHOR).
* **Nmap-style summary** — Target, exploitability band, killchain roles, frameworks, and surface counts before the full JSON.

---

## Install

```bash
pipx install git+https://github.com/Pa7ch3s/Unveil.git
```

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

```bash
unveil -C /path/to/target -xj report.json
```

> *All output is JSON. Designed to drop directly into pipelines, tooling, and reports.*

---

## License

MIT
