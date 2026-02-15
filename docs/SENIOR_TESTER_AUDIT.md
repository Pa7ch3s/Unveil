# Senior Thick-Client Tester Audit: What Is Missing?

**Perspective:** A senior penetration tester and SME in thick-client security reviews this tool. The question is: *What would I need to do advanced pen testing from both a static and a dynamic perspective?*

**Current state in one line:** Unveil is a strong **recon and attack-surface mapper** that unifies static discovery (binaries, configs, refs, chainability, checklist, attack graph) and hands off to Burp for HTTP(S). It does **not** yet cover deep static analysis (strings, .NET internals, ACLs, certs) or any real **dynamic** workflow (instrumentation, process monitoring, non-HTTP traffic, credential extraction).

---

## Part 1: Static Perspective — What’s Missing for Advanced Static Testing

### 1.1 Binary and code analysis

| Gap | Today | What a senior tester needs |
|-----|--------|-----------------------------|
| **Strings not in report** | `strings` and entropy are used internally (entropy for packed detection). Raw strings are **not** exposed in the report. | **Harvested strings in report** (or export): URLs, IPs, paths, `http://`, API keys, version strings. Optionally filter by entropy or length so the tester can grep/search without re-running `strings` manually. |
| **.NET: only CLR flag** | PE is tagged as “.NET” if CLR directory is present. No assembly name, version, or dangerous API detection. | **Assembly identity** (name, version) for CVE/catalog lookup. **Dangerous type/method hints**: e.g. `BinaryFormatter`, `ObjectStateFormatter`, `NetDataContractSerializer`, `Type.GetType` from config, remoting endpoints. Even a simple “references System.Runtime.Serialization” style tag would help. |
| **Imports: list only** | Imports are collected and used for classification (Electron, Qt, etc.). Not summarized as “all unique DLLs/symbols” for manual review. | **Import summary** in report (e.g. per binary or globally): “These DLLs are loaded”; “These functions are imported” (optional). Helps answer “does it load suspicious DLLs?” without opening CFF Explorer. |
| **No binary versioning / diff** | No comparison between binaries (e.g. bundled DLL vs. system DLL version). | **Version comparison**: e.g. “Bundled `vcruntime140.dll` version X vs. system Y” for downgrade or DLL sideloading decisions. Optional: “same name, different hash” for tampering checks. |
| **Packed / entropy** | Entropy is computed and used for “packed” tag. No breakdown (which regions, which files). | **Packed/entropy section**: list of high-entropy files or regions so the tester knows what to unpack or skip. Optional: entropy in discovered-asset or findings so it’s visible in UI. |

### 1.2 Configuration and trust boundaries

| Gap | Today | What a senior tester needs |
|-----|--------|-----------------------------|
| **Refs are paths/URLs only** | Reference extraction pulls paths and URLs from XML/JSON/config. No “this config loads this assembly” or binding redirects. | **.NET-specific refs**: e.g. `<assemblyBinding>`, `<probing>`, `codeBase`, `assemblyIdentity`. **Config → load chain**: “File X references assembly Y” so chainability includes “what gets loaded and from where.” |
| **No ACL / permission analysis** | No file system or registry permission checks. | **Permission auditor**: e.g. “Install dir is writable by Everyone”; “exe has Full Control for Users”; “this registry key is writable.” Directly supports DLL hijack, config tampering, and persistence. |
| **Certs: discovered but not parsed** | Cert files are in discovered_assets (type `cert`). No parsing, expiry, or chain. | **Cert summary**: subject, issuer, validity, key size, and “expired” or “self-signed” flags. Optionally “used by” (which config or binary references it). |
| **APK manifest: no risk scoring** | APK is unpacked and native libs analyzed. No AndroidManifest.xml permission or component analysis. | **Manifest summary**: dangerous permissions, exported components, debuggable, backup, cleartext traffic. Lets the tester prioritize without opening another tool. |

### 1.3 Secrets and checklist

| Gap | Today | What a senior tester needs |
|-----|--------|-----------------------------|
| **Fixed checklist patterns** | Checklist has a good set of patterns (JWT, API keys, disabled SSL, etc.). No custom rules. | **Custom patterns** (regex or simple rules) so the team can add client-specific or new secret formats without changing code. |
| **No prioritization** | All checklist findings are equal in the report. | **Severity or tag** (e.g. “credential”, “dangerous config”, “informational”) so the tester can sort by impact. |
| **Snippet only** | Findings include file, pattern, snippet, line. No “full line” or “surrounding context” option. | **Optional context** (e.g. ±2 lines) for paste into reports or follow-up. |

### 1.4 Attack graph and CVE

| Gap | Today | What a senior tester needs |
|-----|--------|-----------------------------|
| **CVE: hunt queries only** | Report has `possible_cves` / hunt_queries; user pastes into NVD. No automatic lookup. | **Optional CVE lookup** (e.g. by product/version from specs or Electron version) so the report can say “Known CVEs: CVE-2020-…” with link. Offline or cached DB is enough for many testers. |
| **Chains are generic** | Chains are “missing role → surface → hunt targets” with matched paths. No “confidence” or “evidence” level. | **Confidence or evidence**: e.g. “High: we found preload.js and ASAR path”; “Low: Qt in path but no qt.conf.” Helps the tester decide what to verify first. |
| **No “test this first” order** | Chains and URLs are listed; no explicit prioritization. | **Suggested order**: e.g. by chain completion, by “has matched_paths,” or by surface type (ANCHOR before BRIDGE) so the report suggests “test 1, 2, 3.” |

---

## Part 2: Dynamic Perspective — What’s Missing for Advanced Dynamic Testing

### 2.1 Traffic and proxy

| Gap | Today | What a senior tester needs |
|-----|--------|-----------------------------|
| **HTTP(S) only in UI** | Send to Repeater and Live manipulation are for http(s) URLs. Non-HTTP traffic (raw TCP, WebSockets, gRPC, custom protocols) is out of scope. | **Non-HTTP awareness**: list or tag “likely WebSocket/raw TCP” from refs or config (e.g. `ws://`, port-only refs). At least document “for non-HTTP use Burp’s listener + app proxy settings” and keep proxy env/cert instructions. |
| **No “record from Proxy”** | Live slots are filled from report URLs. User can “Load from Proxy” per slot. | **Bulk “Import from Proxy history”**: e.g. “Import last N requests for this host” so the tester doesn’t manually match report URLs to history. |
| **No replay/diff** | Send request, get response. No baseline vs. modified comparison. | **Optional “diff from baseline”**: store a baseline response per URL and show diff when the same request is sent again (e.g. after config change or hook). |
| **Proxy guidance is copy-paste** | Proxy env and CA instructions are in UI (copy proxy env, copy URL, CA steps). | **One-click “Configure for this app”**: e.g. generate a small script or one-liner that sets proxy + (if possible) launches the app so the tester doesn’t misconfigure. |

### 2.2 Runtime and instrumentation

| Gap | Today | What a senior tester needs |
|-----|--------|-----------------------------|
| **No instrumentation** | No Frida, no hooking, no “run and trace.” Everything is static + manual Burp. | **Instrumentation path**: even a “suggested Frida scripts” or “hook these APIs” list per surface (e.g. “for Electron preload, hook `require(‘child_process’)`”) would bridge static findings to dynamic checks. Full “Frida-lite” UI is a larger feature (see VISION). |
| **No process monitoring** | No ProcMon-style “what did the app touch?” (files, registry, network). | **Process monitor integration**: e.g. “Run app for 60s and capture file/reg access” then merge with static refs (“we predicted X; app actually read Y”). Or at least document recommended tools (ProcMon, fs_usage) and how to correlate with Unveil output. |
| **No debugger/crash** | No attachment to the process, no crash dump or exception monitoring. | **Crash / exception hints**: e.g. “If you attach a debugger, watch for exceptions in these modules” (from attack graph). Optional: “suggested breakpoints” for common vulnerable patterns. |

### 2.3 Credentials and data

| Gap | Today | What a senior tester needs |
|-----|--------|-----------------------------|
| **No credential extraction** | Checklist finds hardcoded secrets in config/script. No OS-level credential access. | **Credential hints**: e.g. “App may use Windows Credential Manager / Keychain / vault” (inferred from imports or config). Optional: link to tools (mimikatz, keychain dump) and what to look for. |
| **No secure storage parsing** | No parsing of app-specific stores (e.g. encrypted config, token cache files). | **Known storage formats**: e.g. “This path looks like Electron safeStorage / token cache; use tool X to decrypt.” Even a short “storage locations by framework” doc would help. |
| **DBs: discovered, not parsed** | .db, .sqlite are in discovered_assets. No schema or sensitive column hint. | **Optional DB summary**: list of DB paths + “contains tables X, Y” or “possible credentials table” so the tester knows what to dump. |

### 2.4 Update and install

| Gap | Today | What a senior tester needs |
|-----|--------|-----------------------------|
| **No update mechanism analysis** | No detection of “how does this app update?” (URLs, signed/unsigned, over HTTP). | **Update discovery**: e.g. refs to “update”, “updater”, “installer”, version-check URLs; tag “possible update over HTTP” for MITM. |
| **No install/uninstall hooks** | No explicit “installer does X” or “uninstall leaves Y.” | **Install artifacts**: e.g. “These paths are often left by installers”; “Check for leftover scheduled tasks / services.” Can be heuristic from persistence + refs. |

---

## Part 3: Summary — What Would Make This “Advanced”?

### Static (must-have for senior use)

1. **Strings (or “interesting strings”) in report** — so the tester doesn’t re-run `strings` and grep by hand.  
2. **.NET: assembly identity + dangerous API / serialization hints** — so .NET apps get the same depth as Electron/Qt.  
3. **ACL / permission audit** — at least “writable by non-admin” on install dir and key binaries.  
4. **Cert parsing** — validity, self-signed, expiry on discovered certs.  
5. **Refinement of refs** — .NET binding/probing and “what loads what” where possible.  
6. **CVE lookup (optional)** — product/version → known CVEs so the report is a one-stop view.

### Static (nice-to-have)

- Import summary and packed/entropy breakdown.  
- APK manifest permissions and components.  
- Custom checklist patterns and severity.  
- Chain confidence and “test this first” order.

### Dynamic (must-have for senior use)

1. **Clear “next step” for non-HTTP** — document or tag “likely non-HTTP” and point to proxy/tooling.  
2. **Bulk “Import from Proxy” for Live manipulation** — so dynamic traffic is easy to align with static URLs.  
3. **Instrumentation roadmap** — “for this surface, consider hooking X” or “run Frida script Y” (even as text/export).  
4. **Process monitor correlation** — doc or feature: “run ProcMon/fs_usage and match with these paths.”

### Dynamic (nice-to-have)

- Credential/storage hints and tool links.  
- Update mechanism tagging.  
- Replay/diff in Live manipulation.  
- Full “Frida-lite” or process monitor integration (longer-term).

---

## Part 4: Prioritized Recommendations

| Priority | Item | Rationale |
|----------|------|-----------|
| **P0** | Strings (or filtered “interesting” strings) in report | Core static need; every thick-client tester greps binaries. |
| **P0** | ACL / permission audit on install dir and key files | Directly enables DLL hijack and tampering decisions. |
| **P0** | .NET: assembly name/version + serialization/dangerous API hints | .NET apps are common; today they’re under-served. |
| **P1** | Cert parsing (validity, self-signed) for discovered certs | Trust boundaries and MITM decisions. |
| **P1** | CVE lookup (product/version → CVE list) | Closes the loop from “possible_cves” to “actual CVEs.” |
| **P1** | Bulk “Import from Proxy history” for Live manipulation | Makes dynamic follow-up on static URLs much faster. |
| **P2** | Instrumentation hints (“hook X”, “run script Y” per surface) | Bridges static findings to Frida/dynamic without building a full hooking UI. |
| **P2** | Custom checklist patterns + severity | Team-specific and client-specific rules. |
| **P2** | Process monitor correlation (doc or feature) | Connects “what we predicted” with “what the app actually did.” |
| **P3** | APK manifest permissions; DB summary; credential/storage hints; update mechanism tagging | Improves coverage and report quality; can follow P0–P2. |

---

**Bottom line:** From a senior thick-client tester’s perspective, the tool is already a strong **recon and attack-surface workbench**. To support **advanced** static testing, the biggest gaps are: **exposing strings**, **.NET depth**, **ACL/permission audit**, **cert parsing**, and **CVE lookup**. For **advanced** dynamic testing, the biggest gaps are: **non-HTTP awareness**, **bulk import from Proxy**, **instrumentation/hooking guidance**, and **process monitor correlation**. Addressing P0 and P1 would make Unveil clearly “advanced”; P2 and P3 would make it best-in-class for thick-client engagements.
