# Thick-client discovery: what’s covered and what isn’t

This doc maps **thick-client pentest phases** to file types and current Unveil behavior, then outlines how to “max” coverage for chainability and recon.

---

## Thick-client phases (simplified)

| Phase | Goal | File types that matter |
|-------|------|-------------------------|
| **Recon / discovery** | What’s in the app? | All binaries, configs, scripts, data, certs |
| **Attack surface** | What’s loadable/writable? | .exe, .dll, .so, .dylib, .js, .asar, plugins, plist |
| **Trust / chainability** | What references what? Who trusts whom? | .xml, .config, .json, .manifest, .policy, .plist, .cert |
| **Persistence / re-exec** | What runs on login/boot? | .plist (Launch*), .xml (Tasks), .vbs/.bat/.ps1/.cmd |
| **Lateral / bridge** | What calls what? IPC, helpers | Binaries + config that define endpoints, paths |
| **Data / staging** | Where is sensitive data? | .db, .sqlite, .log, .xml, .json |

---

## Current coverage in Unveil

- **Binary analysis (full):** `.exe`, `.dll`, `.bin`, `.dylib`, `.so`, `.js` — harvested and classified; feed into surfaces/verdict. **Maxed for “attack surface” on binaries.**
- **Persistence (narrow):**
  - Windows: `.xml` (task/schedule paths only), `.vbs`, `.bat`, `.ps1`, `.cmd`, `.lnk` — only under known persistence dirs (Tasks, Startup, Run, Winlogon, Scripts). **Not maxed:** same extensions elsewhere (e.g. app dirs) are not listed.
  - macOS: `.plist` — only LaunchAgents, LaunchDaemons, Login Items, XPC Info.plist. **Not maxed:** other plists (bundle config, file associations, URL schemes) are ignored.
- **Discovered for interactivity (list only):** `.html`, `.htm` — listed so the analyst can open them. **Maxed for HTML.**
- **Special cases:** `preload.js` (Electron) and specific plist paths are promoted to findings; everything else with those extensions is either ignored or only in persistence context.

So:

- **HTML:** surfaced as “discovered” and openable — **maxed.**
- **XML:** only a small slice (Windows Task XML in persistence dirs) is used; general `.xml` (manifests, app config, policy) is **not** harvested or listed. **Not maxed.**
- **JSON / config:** not harvested or listed. **Not maxed.**
- **Scripts:** only in Windows persistence dirs; scripts in app/bundle dirs are not listed. **Not maxed.**
- **Plist:** only Launch* / XPC; other plists not listed. **Not maxed.**
- **Manifest / policy / cert / data:** not used. **Not maxed.**

---

## Gaps that limit chainability and deeper recon

1. **No unified “discovered assets” by type**  
   Only HTML is collected as “discovered.” XML, JSON, .config, .manifest, .policy, scripts, plists, certs, and data files are either unused or only used in narrow persistence logic. So the analyst can’t “see everything that could matter” in one place or filter by type.

2. **No reference extraction**  
   Config/manifest files often contain paths, URLs, script names, or dependency refs. We don’t parse them to pull out “this XML references that DLL” or “this config loads that script,” so **chainability** (if I control X, what does Y load?) is underused.

3. **Scripts only in persistence paths**  
   .js, .vbs, .ps1, .bat, .cmd elsewhere (e.g. inside an app bundle or install dir) are not listed. For recon and “what can be executed or tampered with,” listing all scripts is important.

4. **Plist / manifest / policy**  
   Full plist coverage (bundle IDs, URL schemes, file associations, entitlements) and Windows manifest/policy would improve trust-boundary and chainability analysis.

5. **Certs and data**  
   .cer, .crt, .pem, .pfx and .db, .sqlite, .log are not harvested; they matter for trust and staging/exfil.

---

## Proposed direction: “discovered assets” by extension/type

- **One conceptual layer:** like `discovered_html`, but for multiple types. Either:
  - A single list of `{ "path": "...", "type": "xml" | "json" | "config" | "script" | "plist" | "manifest" | "cert" | "data" }`, or
  - Separate lists: `discovered_xml`, `discovered_config`, `discovered_scripts`, etc., for simpler UI (tabs/sections per type).

- **Extension → type mapping (example):**

  - **xml** → `.xml` (manifests, app config, policy, Tasks already in persistence; general XML for recon).
  - **json** → `.json` (config, package.json, etc.).
  - **config** → `.config`, `.cfg`, `.ini`, `.yaml`, `.yml` (app/config).
  - **script** → `.js`, `.mjs`, `.cjs`, `.vbs`, `.ps1`, `.bat`, `.cmd` (all locations, not only persistence dirs).
  - **plist** → `.plist` (all; we already use a subset for findings).
  - **manifest** → `.manifest` (Windows SxS, etc.).
  - **policy** → `.policy` (Java/security policy).
  - **cert** → `.cer`, `.crt`, `.pem`, `.pfx`, `.der`.
  - **data** → `.db`, `.sqlite`, `.log` (optional; can be large).

- **Harvest:** Same walk as today (bundles, APK unpack, IPA unpack, DMG, directory). For each file, if extension matches a type, append to that type’s list (with a per-type cap to avoid huge reports). No need to run full binary analysis on these; they’re for listing and later parsing.

- **Report:** Include these lists in the JSON (e.g. `discovered_assets` by type or one list with `type`). HTML export and Burp can show sections/tabs per type (“Discovered XML”, “Discovered config”, …) with Open / Copy path / Copy file:// URL / Export list, same as HTML.

- **Optional next step: reference extraction**  
  Lightweight parsers for a subset of types (e.g. XML, .config, JSON) to extract paths, URLs, script names, and emit “this file references X” in the report. That would feed chainability and “what to hunt next” without changing the rest of the pipeline.

---

## What’s not maxed (summary)

| Area | Current | Not maxed |
|------|---------|-----------|
| **HTML** | Discovered, openable | — |
| **XML** | Only Task XML in persistence dirs | General XML (manifests, config, policy) not listed; no reference extraction |
| **JSON / config** | Unused | Not listed; no reference extraction |
| **Scripts** | Only in Windows persistence dirs | Scripts in app/bundle dirs not listed |
| **Plist** | Only Launch* / XPC for findings | Other plists not listed; no full “discovered plist” |
| **Manifest / policy** | Unused | Not listed |
| **Certs** | Unused | Not listed (trust / chainability) |
| **Data (db, log)** | Unused | Not listed (recon / staging) |
| **Reference extraction** | None | No “file X references path/URL Y” for chainability |

Implementing a **discovered_assets** layer (by type) and then, where useful, **reference extraction** would bring these areas up to a “maxed” level for thick-client recon and chainability.
