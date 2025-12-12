#THC4me — Thick Client Analysis CLI & Daemon

[![build-release](https://github.com/Pa7ch3s/thc4me/actions/workflows/release.yml/badge.svg)](../../actions/workflows/release.yml) 
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A fast static-triage CLI and lightweight HTTP daemon for analyzing executable and mobile package formats.
Supports PE, ELF, Mach-O, APK, IPA, and more.

---
# 🚀 Overview
THC4me provides rapid static inspection of binaries and packages via a command-line interface or REST API.
It extracts metadata, hashes, imports, entropy metrics, and manifest information — ideal for quick local analysis or integration into automated pipelines.

⚙️ Key Features
- 🔍 Fast static scan → JSON output (size, hashes, sections, imports, entropy)
- 🧩 Utilities: strings, imports, entropy, manifest (APK/IPA)
- 🌐 Lightweight API daemon with /health and /scan endpoints
- 📦 Single pure-Python wheel (works with pipx or pip)
- 🧱 Deterministic GitHub Releases through CI/CD

---
# 🧠 Installation
```
Option A – Install from a tagged release
# Replace vX.Y.Z with a valid release tag
pipx install "https://github.com/Pa7ch3s/thc4me/releases/download/vX.Y.Z/thc4me-X.Y.Z-py3-none-any.whl"
# or system-wide
pip install --user "https://github.com/Pa7ch3s/thc4me/releases/download/vX.Y.Z/thc4me-X.Y.Z-py3-none-any.whl"
```

## 💻 CLI Usage
```
# Pretty-print output
thc4me scan /path/to/file | jq

# Save results to file
thc4me scan /path/to/file > result.json
```

---
## 🔗 Daemon Mode
```
# Start HTTP API (default 127.0.0.1:8000)
thc4me-daemon

# Health check
curl -s http://127.0.0.1:8000/health | jq
```

# API Endpoints
```
Method	Endpoint	Description
GET	/health	Returns {"ok": true}
POST	/scan	Accepts { "path": "/absolute/path/to/file", "pretty": true } and returns scan JSON
```
##🧾 Output Schema Example
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
  "manifest": { "...": "APK/IPA manifest or Info.plist data" }
}
```

---
# 🔄 Upgrade
```
pipx uninstall thc4me || true
ver="vX.Y.Z"
pipx install --force "https://github.com/Pa7ch3s/thc4me/releases/download/${ver}/thc4me-${ver#v}-py3-none-any.whl"
```

---
# 🧰 Troubleshooting

##Issue	Fix
404 on wheel URL	Verify version tag and filename on release page
Command not found	Run pipx ensurepath or add ~/.local/bin to PATH
Using Kali/root shell	Prefer non-root user; if root, run:
export PATH="/root/.local/bin:$PATH"

# Uninstall
```
pipx uninstall thc4me
# or
pip uninstall thc4me
```

---
# 🧪 Development
```
git clone git@github.com:Pa7ch3s/thc4me.git
cd thc4me
python -m pip install --upgrade build
python -m build
```

---
# Local install for testing
```
pipx install --force dist/thc4me-*.whl
```

🗺️ Roadmap
- YARA ruleset integration
- Recursive archive triage
- Additional parsers (DEX, .NET)
- Rich HTML reporting
