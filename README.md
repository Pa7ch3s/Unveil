<img width="400" height="376" alt="image" src="https://github.com/user-attachments/assets/7b4f0b20-d5f2-45f6-a0eb-18fb95bb653f" />

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
> * Manifest parsing (APK / IPA)
> * Structured, JSON-first output

---

"Models execution surfaces, trust boundaries, persistence anchors, and lateral bridges... then tells you what to hunt next."

---

## Supported formats

*(presently)*

* Windows PE (.exe / .dll)
* Mach-O (macOS binaries, .app bundles)
* ELF (Linux)
* APK / IPA packages
* ASAR / Electron apps
* JavaScript preload / helper surfaces

---

## Install:

```bash
pipx install git+https://github.com/Pa7ch3s/unv.git
```

---

Verify/Display all available flags:
```
unveil -h
```
<img width="800" height="554" alt="image" src="https://github.com/user-attachments/assets/9cbd824f-a3b6-49ee-b782-aeee6faa208b" />

Core Usage:
(Analyze a single binary, installer, or artifact)
```
unveil -C /path/to/target -xj report.json
```

> *All output is JSON. Designed to drop directly into pipelines, tooling, and reports.*

---

## License

MIT


