# Full Audit: Testing-Phase Depth vs Recon Depth (v0.10.2)

**Purpose:** Map each function/feature to a testing phase and judge whether it operates at **legit depth** for that phase or can **go deeper** into recon.

**Testing phase model (thick-client):**

| Phase | Goal | Typical outputs |
|-------|------|------------------|
| **1. Recon** | Discover what exists: binaries, configs, data, endpoints, dependencies. | File lists, types, imports, strings, versions. |
| **2. Mapping / trust boundaries** | Understand what references what; install surface; load chains. | Refs → assets, chainability, “what loads what.” |
| **3. Vulnerability identification** | Find misconfigs, weak perms, known vulns, dangerous patterns. | Checklist, permissions, certs, CVE, .NET hints. |
| **4. Exploitation support** | Prioritize and hand off: URLs to Repeater, hooks to run, paths to watch. | Attack graph, sendable URLs, instrumentation hints, paths_to_watch. |

---

## 1. Engine & orchestration

| Function / area | Phase | Current depth | Verdict | Notes |
|-----------------|--------|----------------|---------|--------|
| `run()` flow (DMG/IPA/APK/JAR/dir/single-file) | 1–4 | Orchestrates all phases, caps (MAX_FILES, MAX_PER_TYPE, etc.). | **Legit depth** | Clear phases; limits are configurable. |
| `_build_extended_enum()` (ATS, helpers from plists) | 1–2 | Plist-based ATS domains and Electron helper paths. | **Legit depth** | Appropriate for mapping. |
| `_paths_to_watch_from_assets()` | 4 | Target dir + results + discovered paths, cap 300. | **Legit depth** | Good for process-monitor correlation. |

---

## 2. Recon (discovery & static analysis)

### 2.1 Asset discovery

| Function | Phase | Current depth | Verdict | Can go deeper |
|----------|--------|----------------|---------|----------------|
| `collect_discovered_assets()` | 1 | Extension → type (html, xml, json, config, script, plist, cert, data, env, manifest, policy). One list per type, cap per type. | **Legit depth** | **Yes:** Add more types (e.g. `.csproj`, `.nuspec`, `.props` for .NET); optional size/entropy per asset; **APK:** register AndroidManifest.xml as a first-class asset and parse it. |
| `ASSET_EXTENSIONS` | 1 | Fixed set of extensions. | **Legit depth** | **Yes:** .exe.config, .dll.config, .csproj, .sln; AndroidManifest.xml; optional regex or allowlist from config. |

### 2.2 Binary analysis (static_parser)

| Function | Phase | Current depth | Verdict | Can go deeper |
|----------|--------|----------------|---------|----------------|
| `analyze()` | 1 | Imports (lief/otool/ldd/pefile), entropy, file_type (file -b), dotnet (CLR). | **Legit depth** | **Yes:** Export **import summary** (unique DLLs/symbols per binary or globally); optional **export table** for PE. |
| `imports()` / _collect_*_imports | 1 | Library names only (no symbol names). | **Legit depth** | **Yes:** Optional **imported symbol names** (e.g. pefile DIRECTORY_ENTRY_IMPORT[].imports) for “suspicious DLLs/functions” review. |
| `interesting_strings()` | 1 | URLs, IPs, path-like, secret-like patterns from `strings` output; capped per file. | **Legit depth** | **Yes:** Optional entropy filter; version-like strings (e.g. `\d+\.\d+\.\d+`); more secret patterns (e.g. Azure, GCP); **min_len** configurable. |
| `strings()` | 1 | Raw `strings -n min_len`. | **Legit depth** | Fine as-is. |
| `entropy()` | 1 | Per-file Shannon entropy; used for “packed” tag. | **Legit depth** | **Yes:** **Packed/entropy section** in report (which files/regions are high-entropy) so testers know what to unpack. |
| `_is_dotnet_assembly()` | 1 | CLR directory present. | **Legit depth** | No; dotnet_audit handles deeper. |
| `specifications_for_target()` / _pe_specifications | 1 | PE: machine, sizes, subsystem, version resource, string table. | **Legit depth** | **Yes:** Optional **version comparison** (bundled DLL vs system) for sideload/downgrade; more PE optional headers. |
| `manifest()` / _pe_embedded_manifest | 1 | PE embedded app manifest (requestedExecutionLevel). | **Legit depth** | **Yes:** Parse more manifest elements (e.g. dependentAssembly); Mach-O/ELF equivalents if needed. |

### 2.3 Reference extraction (asset_discovery)

| Function | Phase | Current depth | Verdict | Can go deeper |
|----------|--------|----------------|---------|----------------|
| `extract_references()` / _extract_refs_* | 2 | XML (href, path, src, file, key); JSON (path/URL-like values); config (probing, codeBase, privatePath, path, include); plist (URL schemes, bundle ID, doc types); env (path/URL-like). | **Legit depth** | **Yes:** **.NET-specific:** `<assemblyBinding>`, `<assemblyIdentity>`, `<dependentAssembly>` so chainability can show “config X references assembly Y” with identity; **XML:** more namespaces and attributes; **JSON:** nested keys for common app config (e.g. update URLs, API base). |
| `run_reference_extraction()` | 2 | Runs on xml, json, config, plist, env; merges refs per file; cap per type. | **Legit depth** | **Yes:** Include **script** (e.g. .js) for URL/path refs; **manifest** (e.g. .manifest) for assembly refs. |

---

## 3. Mapping & trust boundaries

| Function | Phase | Current depth | Verdict | Can go deeper |
|----------|--------|----------------|---------|----------------|
| `build_chainability()` | 2 | For each (file, ref): in_scope = ref matches discovered path/basename or partial path; matched_type. | **Legit depth** | **Yes:** **Confidence/evidence:** “High: exact path match” vs “Low: basename only”; **.NET load chain:** when refs come from assemblyBinding/codeBase, tag “config → assembly” explicitly. |
| `get_electron_info()` | 2 | package.json: Electron version, nodeIntegration, contextIsolation, sandbox. | **Legit depth** | **Yes:** Parse **preload** path, **asar** flags, **browser window** options from nested config; more package.json keys. |

---

## 4. Vulnerability identification

| Function | Phase | Current depth | Verdict | Can go deeper |
|----------|--------|----------------|---------|----------------|
| `run_checklist()` / `scan_file()` | 3 | Regex patterns (credentials, tokens, disabled SSL, eval, etc.) on config/json/env/script/plist/xml; severity; custom patterns from env. | **Legit depth** | **Yes:** **Optional context** (±2 lines) for findings; **plist:** dedicated patterns (e.g. NSAllowsArbitraryLoads); **script:** more dangerous patterns (e.g. child_process, fs.writeFile); optional **full line** or **multi-line** snippet. |
| `permission_audit.run_audit()` / `audit_path()` | 3 | Windows: icacls → Everyone/Users (F)/(M)/(W). Unix: stat → world/group writable. Target + parent dir; max_depth=0 by default. | **Legit depth** | **Yes:** **Recurse** (max_depth 1–2) into key dirs; **Windows:** explicit ACE parsing (not just first line); **registry** key permissions (optional); **permission_findings** linked to **chainability** (e.g. “writable path is ref’d by X”). |
| `cert_audit.audit_cert()` / `run_cert_audit()` | 3 | openssl x509 -text; subject, issuer, not_before, not_after, expired, self_signed; discovered certs only. | **Legit depth** | **Yes:** **Key size / algorithm**; **chain** (issuer chain); **“used by”** (which config or binary references this cert); **PFX:** extract cert from PFX when possible. |
| `run_dotnet_audit()` / `audit_dotnet_assembly()` | 3 | Assembly name, version, refs_serialization, dangerous_hints (dnfile or monodis/PowerShell). | **Legit depth** | **Yes:** **Config-driven:** parse .exe.config/.dll.config for Type.GetType, remoting endpoints, bindingRedirect; **method bodies** (e.g. IL) for deserialization call sites; **strong name** and **publicKeyToken** for binding. |
| `enrich_report_cve_lookup()` / `lookup_cves_for_query()` | 3 | NVD 2.0 keywordSearch from hunt_queries/possible_cves; product/version heuristic; id, summary, url, score. | **Legit depth** | **Yes:** **CPE-based** search when product/version is known; **version range** (e.g. “Electron &lt; 8.2”); **local/cached CVE DB** option; use **Electron version** from electron_info when present. |

---

## 5. Exploitation support (attack graph & handoff)

| Function | Phase | Current depth | Verdict | Can go deeper |
|----------|--------|----------------|---------|----------------|
| `build_attack_graph()` | 4 | Chains from hunt_plan (role → surface → hunt_targets, matched_paths, suggested_payloads); sendable_urls from hunt_plan + extracted_refs (http(s) only). | **Legit depth** | **Yes:** **Chain confidence/evidence** (e.g. “High: preload.js + ASAR path” vs “Low: Qt in path only”); **suggested order** (e.g. ANCHOR before BRIDGE, or by matched_paths count); **non-HTTP refs** (ws://, port-only) in a separate list or tag. |
| `get_payloads_for_surface()` (payloads.py) | 4 | Per-surface steps/file payloads. | **Legit depth** | **Yes:** More payloads per surface; **templates** that substitute matched_paths; link to CWE/CVE. |
| `build_instrumentation_hints()` | 4 | Per-surface suggestion + frida_hint from SURFACE_HINTS. | **Legit depth** | **Yes:** **Per-chain** hints when multiple surfaces; **script snippets** (e.g. minimal Frida script); **debugger hints** (e.g. “watch these modules”). |
| `enrich_hunt_plan_with_matched_paths()` | 4 | Keywords from hunt_targets → match discovered paths. | **Legit depth** | **Yes:** **Rank** matched_paths by relevance (e.g. preload.js &gt; generic .js); **confidence** per entry. |
| `infer_missing_links()` / MISSING_LINK_TEMPLATES | 4 | Fixed templates per role → hunt_plan. | **Legit depth** | **Yes:** **Dynamic templates** from exploit_families or config; **version-aware** hunt (e.g. “Electron &lt; 8.2” when version known). |

---

## 6. Classifier & verdict (synthesis)

| Function | Phase | Current depth | Verdict | Can go deeper |
|----------|--------|----------------|---------|----------------|
| `classify()` | 1–2 | Path + imports + entropy + dotnet → surfaces/exploits (Electron, Qt, persistence, .NET, Go/Rust/PyInstaller, packed). | **Legit depth** | **Yes:** **Import-based:** e.g. “loads Credential Manager API” → credential hint; **path + content:** e.g. preload content scan for require('child_process'); **version in path** (e.g. Electron 8.1.0 in dir name). |
| `expand()` (surface_expander) | 2 | Adds surfaces from enum (ATS, helpers). | **Legit depth** | Fine as-is. |
| `synthesize()` (surface_synth) | 2–3 | Maps surfaces → EXPLOIT_FAMILIES (impact, CWE, CVE tags, completion_weight). | **Legit depth** | Fine as-is. |
| `compile()` (verdict_compiler) | 3–4 | exploitability_band, missing_roles, hunt_plan, hunt_queries, anchor/bridge_candidates. | **Legit depth** | **Yes:** **Confidence** per missing role; **hunt_plan** entries with **evidence** (e.g. “preload.js found”). |
| `detect_candidates()` (chain_closure) | 2 | Anchor/bridge candidates from findings. | **Legit depth** | No change needed. |

---

## 7. Summary matrix

| Area | Phase | Legit depth? | Can go deeper? |
|------|--------|--------------|-----------------|
| Engine / orchestration | 1–4 | Yes | No (or minor caps). |
| Asset discovery | 1 | Yes | Yes: more types, APK manifest, optional metadata. |
| Binary analysis (imports, entropy, PE, strings) | 1 | Yes | Yes: import summary/symbols, packed breakdown, version diff. |
| Interesting strings | 1 | Yes | Yes: more patterns, entropy filter, version strings. |
| Reference extraction | 2 | Yes | Yes: .NET assemblyIdentity/binding, script refs, manifest. |
| Chainability | 2 | Yes | Yes: confidence, “config → assembly” tag. |
| Electron info | 2 | Yes | Yes: preload path, asar flags, more keys. |
| Checklist | 3 | Yes | Yes: ±2 lines context, plist/script patterns. |
| Permission audit | 3 | Yes | Yes: recurse, ACE detail, registry (optional). |
| Cert audit | 3 | Yes | Yes: key size, chain, “used by,” PFX. |
| .NET audit | 3 | Yes | Yes: config parsing, IL/call sites, strong name. |
| CVE lookup | 3 | Yes | Yes: CPE, version range, Electron version, local DB. |
| Attack graph / payloads / instrumentation | 4 | Yes | Yes: confidence, order, non-HTTP, more payloads. |
| Verdict / hunt_plan | 3–4 | Yes | Yes: evidence, confidence, version-aware hunt. |

---

## 8. Recommended “go deeper” priorities (recon)

1. **Recon:** Import summary (unique DLLs/symbols); packed/entropy report section; optional version comparison for PE.
2. **Mapping:** .NET assemblyBinding/assemblyIdentity in ref extraction and “config → assembly” in chainability; chain confidence/evidence.
3. **Vuln ID:** Checklist ±2 lines context; cert “used by” and key size; .NET config (Type.GetType, remoting); CVE with CPE/version range and Electron version.
4. **Exploitation:** Attack graph confidence and suggested order; non-HTTP refs (ws://, port); optional debugger/crash hints.

This audit reflects **v0.10.2** (CLI and Burp 0.7.3). For concrete issues and P3/nice-to-have items, see **docs/REMAINING_ISSUES.md**.
