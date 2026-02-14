# Remaining issues (post P0–P2)

Concrete issues left from the [Senior Tester Audit](SENIOR_TESTER_AUDIT.md). Copy each block into a GitHub Issue.

---

## P3: APK manifest permissions

**Title:** P3: APK manifest – parse AndroidManifest.xml for permissions and components

**Description:**

Parse `AndroidManifest.xml` from unpacked APKs and add a report section (e.g. `apk_manifest`) with:

- Dangerous permissions (e.g. INTERNET, READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE, BIND_*)
- Exported components (activities, services, receivers) and whether they have intent-filters
- Flags: debuggable, backupAllowed, usesCleartextTraffic (or equivalent)

Expose in Burp (e.g. new tab or subsection) so testers can prioritize without opening another tool.

**Acceptance:** Report contains structured APK manifest summary; optional Burp UI to view it.

---

## P3: DB summary for discovered databases

**Title:** P3: Optional DB summary for discovered .db / .sqlite assets

**Description:**

For assets of type `data` (e.g. `.db`, `.sqlite`), optionally:

- Open read-only and list table names (and optionally column names)
- Heuristic: flag “possible credentials table” (e.g. table name contains user/pass/credential/token)
- Add report key `db_summary`: list of `{path, tables[], possible_credentials_hint}` (capped)

No need to parse full schema; lightweight SQLite attach + PRAGMA table_list is enough. Skip or cap large DBs.

**Acceptance:** Report includes `db_summary` when such assets exist; optional Burp display.

---

## P3: Credential and storage hints

**Title:** P3: Credential and secure-storage hints (Keychain, Credential Manager, safeStorage)

**Description:**

- Infer from imports or config: “App may use Windows Credential Manager / Keychain / vault” (e.g. keychain, credman, DPAPI, Electron safeStorage)
- Add report section or checklist-style `credential_hints` with short text + optional link to tools (e.g. keychain dump, mimikatz)
- Optionally: short doc “Storage locations by framework” (Electron safeStorage path, Qt settings, etc.)

**Acceptance:** Report or doc includes actionable credential/storage hints where inferable.

---

## P3: Update mechanism tagging

**Title:** P3: Update mechanism discovery and tagging (update URLs, over HTTP)

**Description:**

- From extracted refs and discovered assets, detect refs to “update”, “updater”, “installer”, version-check URLs
- Tag entries as “possible update over HTTP” (or similar) when URL is http or host is non-HTTPS for MITM relevance
- Add to report (e.g. `update_refs` or extend `extracted_refs` with a tag) and optionally surface in Burp

**Acceptance:** Report identifies likely update/version-check refs and flags HTTP/non-HTTPS for prioritization.

---

## Nice-to-have: Import summary in report

**Title:** Nice-to-have: Import summary (DLLs/symbols) in report and UI

**Description:**

Today imports are used for classification (Electron, Qt, etc.) but not summarized for manual review. Add:

- Per-binary or global “these DLLs are loaded” / “these functions are imported”
- Optional: list unique DLLs/symbols across all analyzed binaries
- Report key e.g. `import_summary`; optional Burp tab or subsection

**Acceptance:** Report (and optionally UI) exposes import summary for “does it load suspicious DLLs?” without opening CFF Explorer.

---

## Nice-to-have: Packed/entropy breakdown

**Title:** Nice-to-have: Packed/entropy breakdown in report and UI

**Description:**

Entropy is computed and used for “packed” tag internally. Expose:

- List of high-entropy files or regions so testers know what to unpack or skip
- Optional: entropy value in discovered-asset or findings so it’s visible in UI
- Report key e.g. `packed_entropy` or extend findings with entropy where relevant

**Acceptance:** Report (and optionally UI) lists high-entropy files/regions for unpack/skip decisions.

---

## Nice-to-have: Chain confidence and “test this first” order

**Title:** Nice-to-have: Chain confidence/evidence and suggested test order

**Description:**

- Add “confidence” or “evidence” level per chain (e.g. “High: we found preload.js and ASAR path”; “Low: Qt in path but no qt.conf”)
- Add suggested order: e.g. by chain completion, by “has matched_paths”, or by surface type (ANCHOR before BRIDGE) so report suggests “test 1, 2, 3”
- Report and Burp Attack graph tab: show confidence and order

**Acceptance:** Chains have confidence/evidence and a suggested test order in report and UI.

---

## Nice-to-have: Checklist optional context (±2 lines)

**Title:** Nice-to-have: Checklist optional context (e.g. ±2 lines) for findings

**Description:**

Checklist findings include file, pattern, snippet, line. Add optional “full line” or “surrounding context” (e.g. ±2 lines) for paste into reports or follow-up. Configurable (e.g. env or CLI flag) to avoid bloating report.

**Acceptance:** Optional context lines available for checklist findings when enabled.

---

## Nice-to-have: .NET-specific refs (assemblyBinding, probing, codeBase)

**Title:** Nice-to-have: .NET-specific refs and config → load chain

**Description:**

- Extract from configs: `<assemblyBinding>`, `<probing>`, `codeBase`, `assemblyIdentity`
- Add “File X references assembly Y” so chainability includes “what gets loaded and from where”
- Report and chainability UI: show .NET binding/probing refs

**Acceptance:** .NET config refs appear in extracted_refs/chainability and report.

---

## Dynamic: Non-HTTP awareness

**Title:** Dynamic: Non-HTTP awareness (WebSocket, raw TCP) and doc

**Description:**

- Tag or list “likely WebSocket/raw TCP” from refs (e.g. `ws://`, port-only refs)
- Document in UI or README: “For non-HTTP use Burp’s listener + app proxy settings” and keep proxy env/cert instructions
- Optional: small report key `non_http_refs` for ws:// or port-only URLs

**Acceptance:** Testers can identify and document non-HTTP endpoints; doc points to proxy/tooling.

---

## Dynamic: Replay/diff from baseline in Live manipulation

**Title:** Dynamic: Optional “diff from baseline” in Live manipulation

**Description:**

- Store a baseline response per URL (e.g. first response after load)
- When the same request is sent again, show diff (e.g. line-by-line or unified diff) between baseline and current response
- Useful after config change or hook to see what changed

**Acceptance:** Burp Live manipulation can store baseline and show diff on subsequent Send.

---

## Dynamic: One-click “Configure for this app”

**Title:** Dynamic: One-click “Configure for this app” (proxy + launch script)

**Description:**

- Generate a small script or one-liner that sets proxy env (e.g. HTTP_PROXY, HTTPS_PROXY to Burp) and optionally launches the app
- Reduces misconfiguration; could be per-target or from report
- Burp: button “Copy configure script” or “Generate launch script”

**Acceptance:** User can copy a script that sets proxy and (if possible) launches the app.

---

## Dynamic: Crash/debugger hints (optional)

**Title:** Dynamic: Optional crash/debugger hints from attack graph

**Description:**

- From attack graph surfaces, suggest “If you attach a debugger, watch for exceptions in these modules”
- Optional: “suggested breakpoints” for common vulnerable patterns (e.g. deserialization, load)
- Report key e.g. `debugger_hints` or extend instrumentation_hints

**Acceptance:** Report (and optionally UI) includes debugger/exception hints where relevant.

---

## Optional: Binary versioning / diff

**Title:** Optional: Binary versioning and diff (bundled vs system DLL)

**Description:**

- Compare bundled DLL vs system DLL version (e.g. vcruntime140.dll) for downgrade or DLL sideloading decisions
- Optional: “same name, different hash” for tampering checks
- Report key e.g. `version_diff` or add to discovered_assets metadata

**Acceptance:** Report can include version comparison or hash diff for key binaries when applicable.
