# THC4ME — Thick Client Extension (CLI + Daemon)

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
