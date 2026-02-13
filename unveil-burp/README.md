# Unveil — Burp Suite extension

Adds an **Unveil** tab to Burp Suite: scan apps/binaries for attack surfaces, set CLI options via checkboxes, and view compressed results (Summary, Hunt plan table, Raw JSON) with Copy / Save / Export HTML.

## What’s in the tab

- **Path** — Target to scan: directory, `.app`, `.exe`, `.dmg`, `.ipa`, `.apk`, or file. **Browse…** to pick (starts in /Applications when empty).
- **Scan** — Runs the Unveil CLI with the path and selected options; results appear in the tabbed area below.
- **Options** — **Extended (-e)**, **Offensive (-O)**, **Force (-f)** checkboxes (same as CLI).
- **Unveil executable (optional)** — Override path to the `unveil` binary; **Browse…** to select any file. Leave empty to auto-detect. **Unveil CLI:** label shows detected version.
- **Results** — **Summary** (verdict, exploitability band, missing roles), **Hunt plan** (table), **Raw JSON**.
- **Copy JSON** / **Save JSON…** / **Save compact JSON…** / **Export HTML…** — Copy, save indented or compact JSON, or export HTML via `unveil -xh`. Buttons are no-ops when there is no report; Export HTML is disabled while exporting.
- **Rescan last** — Re-run the last successful scan target without re-entering the path.
- **Hunt plan** — Table is sortable by column; **Filter** field filters rows by text in any column (cleared when a new report is loaded).

## Unveil CLI ↔ UI mapping

| CLI | Extension |
|-----|-----------|
| `-C`, `--target` (required) | **Path** field + **Browse…** |
| `-e` | **Extended (-e)** checkbox |
| `-O` | **Offensive (-O)** checkbox |
| `-f` | **Force (-f)** checkbox |
| `-q` | Always used for scan (no banner in UI) |
| `-xj FILE` | Scan writes to temp file; **Save JSON…** saves indented from buffer |
| `-xx FILE` | **Save compact JSON…** (single-line JSON) |
| `-xh FILE` | **Export HTML…** runs `unveil -q -xh <file>` |
| `--version` | **Unveil CLI:** label (fetched on load) |

All scan target types (directory, .app, single file, .dmg, .ipa, .apk) are supported via the same **Path** field.

## Build

**Requirements:** Java 17+, Gradle 7+.

```bash
cd unveil-burp
./gradlew jar
```

The JAR is written to `build/libs/unveil-burp-0.1.0.jar`.

## Load in Burp

1. Open Burp Suite (2023.8+ for Montoya API).
2. **Extensions** → **Installed** → **Add** → **Extension type: Java**.
3. Select `build/libs/unveil-burp-0.1.0.jar`.
4. The **Unveil** tab appears; if scan fails with “unveil not found”, set **Unveil executable (optional)** to the path from `which unveil`.

## Compressing the JSON output

- **Summary** tab shows a short, human-readable verdict (exploitability band, kill chain complete, missing roles, family count, hunt plan count) so you don’t scroll through huge JSON.
- **Hunt plan** tab shows a table: one row per suggestion (missing role, suggested surface, hunt targets, reason). Sortable and scannable.
- **Raw JSON** remains available for tooling or archival; **Copy JSON** / **Save JSON…** / **Save compact JSON…** for sharing or CI.

## Forward-thinking additions

Prioritized ideas that would make the extension more capable and integrated:

1. **Persistent settings** — Remember the last unveil executable path and default option checkboxes across Burp restarts (Montoya persistence API or project-level storage).
2. **Burp Scanner issues** — For each hunt-plan item or verdict, create a Burp finding (confidence, severity, detail from `suggested_surface` / `reason`) so results appear in the Dashboard and issue list.
3. **Send to Repeater/Intruder** — Right-click or button to send a selected hunt target (e.g. a path or artifact) to Burp’s Repeater or Intruder for manual follow-up.
4. **Filter and sort Hunt plan** — Filter by missing role or suggested surface; sort by column so analysts can triage quickly.
5. **Report templates** — One-click export to a chosen format (HTML already; add Markdown or a simple PDF) with optional branding.
6. **Unveil daemon mode** — If the Unveil CLI gains a `POST /scan` HTTP API, the extension could call it instead of spawning a process, for faster repeat scans and less overhead.
7. **Context and remediation** — Tooltips or a panel linking `suggested_surface` and CWE/CVE where applicable; short mitigation hints.
8. **Scan history** — Keep a small list of recent scans (path + timestamp) and allow re-opening the last report without re-scanning.

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
