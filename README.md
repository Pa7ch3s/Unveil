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
> * Manifest parsing (APK / IPA — *planned*)
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
| **APK / IPA** | 🔜 Planned (unpack + manifest not yet implemented) |

---

## Recent features (v0.5.0)

* **DMG support** — Pass a `.dmg` path; Unveil mounts it, discovers `.app` bundles, runs the full pipeline, then unmounts.
* **Electron pack** — Preload/ASAR write surfaces, helper/IPC/crashpad bridges, ANCHOR/BRIDGE classification.
* **Qt pack** — Qt plugin rpath hijack (ANCHOR), qt.conf and plugin path detection.
* **macOS persistence pack** — LaunchAgents, LaunchDaemons, Login Items, XPC; plists in those paths are harvested and tagged.
* **Nmap-style summary** — Target, exploitability band, killchain roles, frameworks, and surface counts before the full JSON.

---

## Install

```bash
pipx install git+https://github.com/Pa7ch3s/Unveil.git
```

**Upgrading from `unv`:** The CLI was renamed to `unveil`. If you still see `unv` or `unv-daemon` when you tab-complete, remove the old scripts and reinstall:

```bash
pipx uninstall unv 2>/dev/null; pipx uninstall unveil 2>/dev/null
rm -f ~/.local/bin/unv ~/.local/bin/unv-daemon
pipx install git+https://github.com/Pa7ch3s/Unveil.git
```

If the binaries live elsewhere, find them with `which unv` and `which unv-daemon`, then delete those paths. Open a new terminal (or run `hash -r`) so completions refresh.

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
