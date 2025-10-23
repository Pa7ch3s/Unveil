# thc4me.py — Thick Client Extension (CLI + Daemon)

[![build-release](https://github.com/Pa7ch3s/thc4me/actions/workflows/release.yml/badge.svg)](../../actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Static-triage CLI and lightweight HTTP daemon for quick file inspection. Supports PE, ELF, Mach-O, APK, IPA.

---

## Features

- Fast scan → JSON: size, hashes, sections, imports, entropy.
- Utilities: `strings`, `imports`, `entropy`, `manifest` (APK/IPA).
- Local API daemon with `/health` and JSON responses.
- Single pure-Python wheel. Works with `pipx` or `pip`.
- Deterministic GitHub Releases via CI.

---

## Install

### Option A: pick a tag
```bash
# replace vX.Y.Z with the release you want
pipx install "https://github.com/Pa7ch3s/thc4me/releases/download/vX.Y.Z/thc4me-X.Y.Z-py3-none-any.whl"
# or system-wide user install
pip install --user "https://github.com/Pa7ch3s/thc4me/releases/download/vX.Y.Z/thc4me-X.Y.Z-py3-none-any.whl"
```
---

# Daemon

```
start HTTP API on 127.0.0.1:8000
thc4me-daemon
#health check
curl -s http://127.0.0.1:8000/health | jq
```

API (daemon)
### GET /health → {"ok": true}
### POST /scan body:
```
{ "path": "/absolute/path/to/file", "pretty": true }
```

Response: same structure as thc4me scan.

Output schema (scan)
```
{
  "path": "...",
  "size": 12345,
  "hashes": { "md5": "...", "sha1": "...", "sha256": "..." },
  "type": "PE|ELF|Mach-O|APK|IPA|Unknown",
  "sections": [{ "name": ".text", "size": 4096, "entropy": 6.7 }],
  "imports": [{ "library": "kernel32.dll", "symbols": ["CreateFileA", "..."] }],
  "strings": { "count": 321, "sample": ["http://...", "User-Agent", "..."] },
  "entropy": { "overall": 5.8, "suspicious": false },
  "manifest": { "...": "APK/IPA manifest or Info.plist, if applicable" }
}
```

---

# Upgrade

```
#remove old
pipx uninstall thc4me || true

#install new tag
ver="vX.Y.Z"
pipx install --force "https://github.com/Pa7ch3s/thc4me/releases/download/${ver}/thc4me-${ver#v}-py3-none-any.whl"
```

---

# Troubleshooting

* 404 on wheel URL
Use an existing tag and exact filename from the release page.

* Command not found after install
Add ~/.local/bin to PATH (pipx ensurepath).

* Kali / root shells
Prefer non-root user for pipx. If you must run as root, export PATH explicitly:

```
export PATH="/root/.local/bin:$PATH"
```

### Uninstall
pipx uninstall thc4me or pip uninstall thc4me.

---

# Development
```
git clone git@github.com:Pa7ch3s/thc4me.git
cd thc4me
python -m pip install --upgrade build
python -m build

#run locally
pipx install --force dist/thc4me-*.whl
```

---

# Roadmap

* YARA ruleset hook.

* Recursive archive triage.

* More parsers (DEX, .NET).

* Rich HTML report.
