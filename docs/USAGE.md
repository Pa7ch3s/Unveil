# Unveil — Usage

Step-by-step commands with full syntax. Add a screenshot below each example if desired.

---

## 1. Show version

```bash
unveil --version
```

Displays the installed Unveil version (e.g. `Unveil RADAR v0.5.0`).

---

## 2. Show help and all options

```bash
unveil -h
```

Lists all flags: `-C` (target), `-e`, `-O`, `-f`, `-q`, `-xh`, `-xj`, `-xx`.

---

## 3. Scan a directory or application bundle (default output)

```bash
unveil -C /path/to/target
```

- **Target:** Directory or `.app` bundle.
- **Output:** Banner, Nmap-style summary (target, exploitability, killchain roles, frameworks, surface counts), then full JSON to stdout.
- **Example (macOS app):**
  ```bash
  unveil -C /Applications/Safari.app
  ```
- **Example (Windows directory):**
  ```bash
  unveil -C "C:\Program Files\MyApp"
  ```

---

## 4. Scan a single file (binary or script)

```bash
unveil -C /path/to/file.exe
```

- **Target:** A single file (e.g. `.exe`, `.dll`, `.so`, `.dylib`, `.js`).
- **Output:** Banner, then JSON for that file only (no bundle walk).

**Examples:**

```bash
unveil -C ./suspicious.exe
unveil -C /usr/lib/libfoo.so
```

---

## 5. Scan a DMG (macOS disk image)

```bash
unveil -C /path/to/image.dmg
```

- Unveil mounts the DMG, discovers `.app` bundles inside, runs the full radar, then unmounts.
- **Output:** Same as directory scan; `metadata.target` stays the original `.dmg` path.

---

## 6. Scan an IPA (iOS app)

```bash
unveil -C /path/to/app.ipa
```

- Unveil unpacks the IPA, scans `Payload/*.app` like macOS bundles (Mach-O, plists), then removes the temp unpack.
- **Output:** Same structure as a directory scan of an `.app`.

---

## 7. Scan an APK (Android app)

```bash
unveil -C /path/to/app.apk
```

- Unveil unpacks the APK, harvests and analyzes `lib/*/*.so` (ELF), then removes the temp unpack.
- **Output:** Same structure; surfaces come from native libs.

---

## 8. Quiet mode (no banner, no pretty-printed summary)

```bash
unveil -C /path/to/target -q
```

- Suppresses the ASCII banner and the human-readable summary; only raw JSON is printed.
- Useful for piping or CI.

---

## 9. Extended surface expansion

```bash
unveil -C /path/to/target -e
```

- Enables deeper persistence and lateral surface expansion in the reasoning layer.
- Use when you want more surfaces and chain hints.

---

## 10. Offensive surface synthesis

```bash
unveil -C /path/to/target -O
```

- Enables exploit-chain modeling (offensive surface synthesis) in the report.
- Use for hunt plans and chain completion.

---

## 11. Force analysis of unsigned or malformed binaries

```bash
unveil -C /path/to/target -f
```

- Tells the pipeline to attempt analysis even when binaries are unsigned or malformed (e.g. skip strict validation).
- Use when triaging untrusted or broken artifacts.

---

## 12. Export report to HTML

```bash
unveil -C /path/to/target -xh report.html
```

- Runs the scan and writes a pretty-rendered HTML report to `report.html`.
- Stdout still gets the default output (banner + summary + JSON) unless you also use `-q`.

---

## 13. Export full JSON report (indented)

```bash
unveil -C /path/to/target -xj report.json
```

- Writes the full indented JSON report to `report.json`.
- Use for tooling, archiving, or further processing.

---

## 14. Export compact raw JSON

```bash
unveil -C /path/to/target -xx report.json
```

- Writes the same report as a single-line (compact) JSON file.
- Use for minimal file size or strict JSON parsers.

---

## 15. Quiet + JSON export (CI / pipeline)

```bash
unveil -C /path/to/target -q -xj report.json
```

- No banner, no summary; JSON is written to `report.json` and nothing (or minimal) goes to stdout.
- Good for scripts and CI.

---

## 16. Combined options (extended + offensive + export)

```bash
unveil -C /path/to/target -e -O -xj report.json
```

- Extended expansion, offensive synthesis, and indented JSON export in one run.

---

## 17. Scan and export HTML without terminal JSON

```bash
unveil -C /path/to/target -q -xh report.html
```

- Quiet run; only the HTML file is produced (no JSON to stdout).

---

## Quick reference: all flags

| Flag | Meaning |
|------|--------|
| `-C`, `--target` | **Required.** Path to directory, .app, file, .dmg, .ipa, or .apk. |
| `-e` | Extended surface expansion. |
| `-O` | Offensive surface synthesis (exploit-chain modeling). |
| `-f` | Force analysis of unsigned/malformed binaries. |
| `-q`, `--quiet` | Suppress banner and pretty summary. |
| `-xh FILE` | Export HTML report to FILE. |
| `-xj FILE` | Export indented JSON report to FILE. |
| `-xx FILE` | Export compact JSON report to FILE. |

---

*Add your screenshots under each section as needed.*
