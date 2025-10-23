# THC4M3 — Thick Client Helper for Burp
![Build](https://github.com/Pa7ch3s/THC4me/actions/workflows/build.yml/badge.svg?branch=main)
[![Release workflow](https://github.com/Pa7ch3s/THC4me/actions/workflows/release.yml/badge.svg)](https://github.com/Pa7ch3s/THC4me/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Static triage CLI and local API for quick file inspection. Supports PE, ELF, Mach-O, APK, and IPA.

## Features
- Fast scan to JSON: hashes, size, sections, imports, entropy
- Strings, imports, and entropy utilities
- APK/IPA manifest dump
- Local API daemon with `/health`
- Single binary wheel, `pipx` friendly
- Deterministic GitHub Releases with CI

## Install
### Option A: pipx
```bash
pipx install https://github.com/Pa7ch3s/thc4me/releases/latest/download/thc4me-$(curl -s https://api.github.com/repos/Pa7ch3s/thc4me/releases/latest | python -c 'import sys,json; r=json.load(sys.stdin); print(r["tag_name"].lstrip("v"))')-py3-none-any.whl
