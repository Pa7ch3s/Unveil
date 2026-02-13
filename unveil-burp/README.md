# Unveil — Burp Suite extension

Adds an **Unveil** tab to Burp Suite: scan apps/binaries for attack surfaces, set CLI options or use the **daemon**, and view rich results (Summary, Hunt plan, Electron info, Chainability, Extracted refs, Possible CVEs, Discovered assets, Raw JSON) with Copy / Save / Export HTML / **Export SARIF**.

## What’s in the tab (v0.3.0)

- **Path** — Target to scan: directory, `.app`, `.exe`, `.dmg`, `.ipa`, `.apk`, `.jar`/`.war`, or file. **Browse…** to pick.
- **Scan** — Runs the Unveil CLI (or **daemon** if enabled) with the path and options; results appear below.
- **Options** — **Extended (-e)**, **Offensive (-O)**, **Force (-f)**, **CVE (--cve)** checkboxes.
- **Use daemon** — Call `POST /scan` at the given URL instead of spawning the CLI (faster repeat scans). Default URL: `http://127.0.0.1:8000`. Start the daemon with `unveil` (see main repo) or run `python -m unveil.daemon`.
- **Limits** — **Max files**, **Max size (MB)**, **Max per type** (CLI `--max-files`, `--max-size-mb`, `--max-per-type`). Used for both CLI and daemon.
- **Baseline (optional)** — Path to a baseline report JSON; passed as `--baseline` for diff (added/removed findings, verdict changed). Summary shows diff when present.
- **Unveil executable (optional)** — Override path to the `unveil` binary when not using daemon. **Unveil CLI:** label shows detected version.
- **Results tabs** — **Summary** (verdict, electron/chainability/CVE counts, baseline diff), **Hunt plan**, **Discovered HTML**, **Discovered assets** (incl. **env**), **Electron info**, **Chainability**, **Extracted refs**, **Possible CVEs**, **Raw JSON**.
- **Copy JSON** / **Save JSON…** / **Save compact JSON…** / **Export HTML…** / **Export SARIF…** — Export SARIF runs `unveil -q -xs <file>` for CI/IDE.
- **Persistent settings** — Unveil path, daemon URL, option checkboxes, limits, and baseline path are saved and restored across Burp restarts (Java Preferences).
- **Rescan last** — Re-run the last target (CLI or daemon).

## Unveil CLI ↔ UI mapping

| CLI / API | Extension |
|-----------|-----------|
| `-C`, `--target` (required) | **Path** field + **Browse…** |
| `-e` | **Extended (-e)** checkbox |
| `-O` | **Offensive (-O)** checkbox |
| `-f` | **Force (-f)** checkbox |
| `--cve` | **CVE (--cve)** checkbox |
| `--max-files`, `--max-size-mb`, `--max-per-type` | **Max files** / **Max size (MB)** / **Max per type** spinners |
| `--baseline FILE` | **Baseline (optional)** + **Browse…** |
| `-q` | Always used for CLI scan (no banner in UI) |
| `-xj` / `-xx` / `-xh` / `-xs` | Save JSON, Save compact, Export HTML, Export SARIF |
| `POST /scan` (daemon) | **Use daemon** + **URL** (same options as JSON body) |
| `--version` | **Unveil CLI:** label (parsed from last line containing RADAR v) |

All scan target types (directory, .app, single file, .dmg, .ipa, .apk) are supported via the same **Path** field. **Discovered HTML** is populated for every mode (bundles, APK unpack, IPA unpack, DMG mount, and single .html/.htm file).

## Build

**Requirements:** Java 17+, Gradle 7+.

```bash
cd unveil-burp
./gradlew jar
```

The JAR is written to `build/libs/unveil-burp-0.3.0.jar`.

## Load in Burp

1. Open Burp Suite (2023.8+ for Montoya API).
2. **Extensions** → **Installed** → **Add** → **Extension type: Java**.
3. Select `build/libs/unveil-burp-0.3.0.jar`.
4. The **Unveil** tab appears; if scan fails with “unveil not found”, set **Unveil executable (optional)** to the path from `which unveil`.

## Compressing the JSON output

- **Summary** tab shows a short, human-readable verdict (exploitability band, kill chain complete, missing roles, family count, hunt plan count) so you don’t scroll through huge JSON.
- **Hunt plan** tab shows a table: one row per suggestion (missing role, suggested surface, hunt targets, reason). Sortable and scannable.
- **Raw JSON** remains available for tooling or archival; **Copy JSON** / **Save JSON…** / **Save compact JSON…** for sharing or CI.

## Implemented (v0.3.0)

- **Persistent settings** — Java Preferences: unveil path, daemon URL, use daemon, option checkboxes, limits, baseline path (saved on successful scan).
- **Daemon mode** — **Use daemon** + URL; `POST /scan` with JSON body (target, extended, offensive, max_files, max_size_mb, max_per_type). No CLI spawn.
- **New report tabs** — **Electron info** (version, nodeIntegration, contextIsolation, sandbox), **Chainability** (file → ref → in scope / matched type), **Extracted refs** (file → refs), **Possible CVEs** (hunt_queries / possible_cves; Copy all).
- **Summary** — Now includes electron info present, chainability count (refs / in scope), possible CVE count, and **baseline diff** (added/removed findings, verdict changed) when `--baseline` was used.
- **Export SARIF…** — Runs `unveil -q -xs <file>` for CI (e.g. GitHub Code Scanning).
- **Limits & baseline** — UI for `--max-files`, `--max-size-mb`, `--max-per-type`, `--baseline`; **env** in Discovered assets type filter.
- **Version label** — Parses “Unveil RADAR vX.Y.Z” from CLI output (handles multi-line banner).

## Forward-thinking additions

1. **Burp Scanner issues** — Create Burp findings from verdict/hunt_plan for Dashboard and issue list.
2. **Send to Repeater/Intruder** — Send selected hunt target or path to Repeater/Intruder.
3. **Report templates** — Markdown or PDF export with branding.
4. **Context and remediation** — Tooltips linking suggested_surface to CWE/CVE and mitigation.
5. **Scan history** — List of recent scans (path + timestamp) and re-open last report without re-scanning.

## Roadmap

Ideas to take this from “useful plugin” to best-in-class:

- **Burp integration** — Create Burp Scanner issues from verdict/hunt_plan; send selected hunt targets to Repeater/Intruder; surface in Target/Dashboard.
- **Prioritization & scoring** — Sort/filter hunt plan by impact or chain completion; risk bands and custom weights.
- **Context & remediation** — Inline docs for suggested surfaces; links to CVEs, advisories, or mitigation steps.
- **Persistent config** — Save unveil path and default options so they survive restarts.
- **Reporting** — One-click HTML/PDF/Markdown reports with branding and optional sections.
- **Daemon mode** — Optional Unveil daemon + `POST /scan` for faster repeat scans and less process overhead.
- **Verification / PoC** — Buttons to generate or run proof-of-concept payloads for selected surfaces (with appropriate safeguards).
- **Extensibility** — Custom surfaces or modules that plug into the same report format.

## API version

Built against `montoya-api:2023.8`. If your Burp version is different, change the version in `build.gradle.kts` to match (see [Maven Central](https://central.sonatype.com/artifact/net.portswigger.burp.extensions/montoya-api)).

## Disclaimer

This tool is for educational purposes and authorized security testing only. Unauthorized use against systems without prior written consent is strictly prohibited.
