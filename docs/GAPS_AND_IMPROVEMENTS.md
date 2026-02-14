# Gaps and improvements for new thick-client testers

This doc analyzes where Unveil is **lacking support or missing connections** for people new to thick-client testing, from a **functionality**, **logistical**, **materialistic**, and **onboarding** perspective. Each section ends with concrete improvements that can help.

**Code-level changes** (CLI and Burp UI behavior, validation, errors) are tracked and implemented in **[docs/CLI_UI_IMPROVEMENTS.md](CLI_UI_IMPROVEMENTS.md)**.

---

## 1. Functionality gaps

| Gap | Impact on new testers | Possible improvement |
|-----|------------------------|----------------------|
| **No “what to do next” per finding** | Report shows surfaces and chains but not *how* to test them (e.g. “Check for weak padding” for crypto refs). | Add short “Next step” or “Manual test” hints in attack graph / checklist (or link to [VISION](VISION.md) test-case mapping when implemented). |
| **-e vs -O unclear** | New users don’t know when to use Extended vs Offensive; default scan may feel “incomplete.” | Document in README/USAGE: “Use `-e` for persistence/helper discovery; use `-O` for full exploit-chain modeling. For a first pass, try both.” |
| **Single file vs directory** | Scanning a single `.exe` gives different output than a directory; not obvious which to choose. | One-line guidance: “Directory or .app for full recon; single file for one binary.” |
| **Daemon underused** | Daemon is faster for repeat scans but hidden in Advanced; new users stick with CLI. | In Burp: brief tooltip or hint “Use daemon for faster rescans” and one-line “Start daemon: `unveil` or `python -m unveil.daemon`.” |
| **No permission/ACL check** | Weak file permissions (e.g. writable app dir → DLL hijack) are not surfaced. | Future: “Permission auditor” (see [VISION](VISION.md)). For now, document in Vulnerability mapping: “Check ACLs manually where DLL/plugin hijack is in scope.” |
| **Discovery scope confusion** | XML/JSON/scripts are only harvested in certain paths (e.g. persistence dirs); “Discovered assets” is by type but not “everything everywhere.” | In [THICK_CLIENT_DISCOVERY](THICK_CLIENT_DISCOVERY.md) or README: one sentence “Discovery is scoped to bundles, install dirs, and known persistence paths; not a full recursive ‘every file’ list.” |

---

## 2. Logistical gaps (workflow, docs, first run)

| Gap | Impact on new testers | Possible improvement |
|-----|------------------------|----------------------|
| **No “first scan in 60 seconds”** | README is dense; no single “do this, then this” path. | Add **Getting started** in README: (1) Install CLI, (2) Run `unveil -C /path/to/app`, (3) Open Summary/attack graph; link to [USAGE](USAGE.md) and this doc. |
| **Burp: “unveil not found”** | Very common; fix is buried in unveil-burp README. | In Burp UI: when scan fails with “not found,” show a short message: “Install CLI: `pipx install git+https://github.com/Pa7ch3s/Unveil.git` then set **Unveil executable** to the path from `which unveil`.” Consider same in status line on failure. |
| **Jargon without definition** | ANCHOR, BRIDGE, BLADE, exploitability_band, chainability appear before they’re explained. | Add **Glossary** (README or [USAGE](USAGE.md)): ANCHOR = persistence/foothold, BRIDGE = lateral movement, BLADE = code execution; exploitability_band = summary risk; chainability = file→ref links. |
| **Report structure not explained** | New testers get JSON/Summary but don’t know what `attack_graph`, `checklist_findings`, `discovered_assets` mean or where to look. | One-page **Understanding the report** (this doc or README): “Summary = high-level; Attack graph = what to hunt; Checklist = secrets/config risks; Discovered assets = files by type; Chainability = what references what.” |
| **No troubleshooting** | DMG mount fails, IPA/APK unpack fails, “file not found,” or empty report—no central place to look. | Add **Troubleshooting** section: “DMG: needs macOS, mount point; IPA/APK: unzip/temp space; Empty report: try `-e -O`, check path; Burp: set Unveil executable path.” |
| **CLI vs Burp vs both** | Unclear whether to use CLI only, Burp only, or both. | One sentence: “CLI for automation and CI; Burp for interactive testing and Send to Repeater. Use both: CLI for first recon, Burp for follow-up and proxy workflow.” |

---

## 3. Materialistic gaps (platform, dependencies, resources)

| Gap | Impact on new testers | Possible improvement |
|-----|------------------------|----------------------|
| **Platform requirements not stated in one place** | Assumptions (macOS for DMG, Windows paths, Java 17 for Burp) are scattered. | In README **Install**: “CLI: Python 3.9+, macOS/Linux/Windows. Burp extension: Java 17+, Burp Suite 2023.8+. DMG scan: macOS only. Optional: lief (faster Mach-O/ELF).” |
| **Burp JAR not in GitHub Releases** | Users must build with Gradle; non-Java testers hit a wall. | Consider attaching `unveil-burp-0.6.0.jar` (or current version) to Releases so “Download JAR → Load in Burp” is possible without Gradle. |
| **Temp/disk for DMG/IPA/APK** | Unpack and mount need space; large targets can fail or be slow. | In USAGE or Troubleshooting: “DMG/IPA/APK use temp dirs; ensure enough disk space; use `--max-files` / `--max-size-mb` for large targets.” |
| **Proxy/Burp CA not in main flow** | Sending traffic to Burp requires proxy + CA; mentioned in payloads but not in a “Setup” section. | Short **Proxy setup** (README or docs): “Set HTTP_PROXY/HTTPS_PROXY; install Burp CA (e.g. certutil or Keychain); checklist flags disabled cert validation.” Link from Vulnerability mapping (TLS row). |

---

## 4. Conceptual / onboarding gaps

| Gap | Impact on new testers | Possible improvement |
|-----|------------------------|----------------------|
| **No mental model of “kill chain”** | Missing roles (ANCHOR/BRIDGE/BLADE) and “chain completion” are opaque. | Glossary + one sentence: “Unveil models a simple chain: get a foothold (ANCHOR), move laterally (BRIDGE), achieve code execution (BLADE). The report shows what’s missing.” |
| **No link to thick-client methodology** | New testers don’t know how this fits OWASP or PTES. | In README or Vulnerability mapping: “Aligns with [OWASP thick-client](https://owasp.org/) and desktop app testing; use report as recon input to your methodology.” |
| **“View PoC payloads” underused** | Burp has PoC payloads per chain but no “how to use” in main docs. | In unveil-burp README or main README: “Attack graph → select chain → **View PoC payloads** to copy step-by-step checks (e.g. proxy setup, preload hijack).” |
| **Empty or “low” verdict** | First scan on a simple app may show few surfaces; user thinks the tool isn’t working. | In Troubleshooting or README: “Some targets yield few surfaces by design. Try `-e -O`, a larger install dir, or an Electron/Qt/.NET app for richer output.” |

---

## 5. Summary: high-impact, low-effort improvements

1. **README:** Add **Getting started** (3 steps: install → first scan → where to look) and **Glossary** (ANCHOR/BRIDGE/BLADE, exploitability_band, chainability).
2. **README:** One short **Requirements** line (Python, platform, Burp/Java, optional lief).
3. **Burp:** On “unveil not found” (or scan failure), show install + path hint in status or a small dialog.
4. **Docs:** Add **Troubleshooting** (DMG/IPA/APK, empty report, Burp path) and **Understanding the report** (one page: Summary, attack graph, checklist, assets, chainability).
5. **Releases:** Optionally attach the Burp JAR to GitHub Releases so non-Gradle users can load the extension without building.
6. **USAGE / README:** One sentence each for “when to use -e/-O,” “single file vs directory,” “CLI vs Burp vs both,” and “proxy setup” link.

These close the main **logistical** and **onboarding** gaps so new thick-client testers can run a first scan, interpret the output, and know where to look when something fails.
