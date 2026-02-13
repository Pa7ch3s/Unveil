# Changelog

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
