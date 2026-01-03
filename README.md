## 🩸 Unveil

Attack Path Discovery Engine

>*From binary to breach path.*
---
Performs fast, local static triage on binaries, apps, and packages; turning opaque artifacts into structured, actionable intel.

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

## Install

```bash
pipx install git+https://github.com/Pa7ch3s/unv.git
```

---

## Usage

```bash
unveil -C /path/to/target -xj output.json

unv scan /path/to/target
unv strings /path/to/target
unv entropy /path/to/target
```

> *All output is JSON. Designed to drop directly into pipelines, tooling, and reports.*

---

## License

MIT


