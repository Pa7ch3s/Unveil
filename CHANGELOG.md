# Changelog

## [Unreleased]

- **Discovered assets by type** — Report includes `discovered_assets` (html, xml, json, config, script, plist, manifest, policy, cert, data) with per-type caps; `discovered_html` kept for backward compatibility.
- **Reference extraction** — Lightweight parsing of XML, JSON, and .config (size-capped) to extract paths/URLs; `extracted_refs` in report for chainability.
- **HTML report** — Sections for discovered assets by type and extracted references.
- **Burp** — “Discovered assets” tab with Path/Type table, type filter, Open / Copy path / Copy file:// URL / Export list; context menu and double-click to open.
- **Professional pentest** — Aligns with thick-client testing methodology; README note on OWASP and professional use.

## [0.2.0] — unveil-burp (Burp Suite extension)

- Full Unveil CLI options in UI: Path, Extended (-e), Offensive (-O), Force (-f), optional unveil executable path with Browse.
- Results: Summary, Hunt plan (sortable table + filter), Raw JSON; Copy JSON, Save JSON, Save compact JSON, Export HTML.
- Rescan last target; guard empty report on save/copy; single-author project.

---

## [0.6.0] — CLI

- **Mobile (APK / IPA)** — Unpack and scan; native libs (APK) or `.app` bundles (IPA).
- **Windows persistence pack** — Run/Services, Scheduled Tasks, Startup, Winlogon, Scripts; harvest and tag `.xml`, `.vbs`, `.bat`, `.ps1`, `.cmd`.
- **.NET pack** — Detect CLR assemblies (PE); deserialization, remoting, assembly-load surfaces (ANCHOR).
- **Windows binary harvest** — `.dll` in scope; when no `.app` bundles, harvest `.exe`/`.dll` from directory tree.
- **Docs** — Full usage section on README; step-by-step commands in README and `docs/USAGE.md`.
- **Tagline** — "Opaque binaries in. Attack surfaces out."

## [0.5.0]

- DMG support (mount and scan).
- Electron, Qt, macOS persistence packs.
- Nmap-style summary; banner and plist noise filter.
- Rename unv → unveil; single CLI.
