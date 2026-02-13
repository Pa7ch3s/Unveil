# Unveil – Tool Audit & Optimization Notes

**Date:** 2026-02-13  
**Scope:** CLI, engine, classifier, static parser, surface expansion/synthesis, verdict, assets, export, daemon.

---

## 1. Architecture Summary

| Component | Role |
|-----------|------|
| **cli.py** | Argument parsing, banner, `run(target)`, pretty print, export (-xh/-xj/-xx). |
| **engine.py** | Target dispatch (file/dir/DMG/IPA/APK), harvest (bundles, dir binaries, Windows persistence, APK libs), `build_reasoning()` → expand → normalize → synthesize → verdict. |
| **static_parser.py** | `analyze()`: file type (file/otool/ldd/pefile), imports, entropy, .NET CLR tag. Uses subprocess for `file`, `otool`, `ldd`, `strings`. |
| **classifier.py** | Maps analysis → surfaces + exploits (Electron, Qt, macOS/Windows persistence, .NET, packed). |
| **surface_expander.py** | Maps indicator classes → surface records (trust boundary, reentry, impact). |
| **surface_synth.py** | Maps surfaces → EXPLOIT_FAMILIES intel (CWE, CVE tags, killchain role, completion_weight). |
| **verdict_compiler.py** | Aggregates synth → exploitability band, missing roles, hunt_plan (via missing_link_engine). |
| **chain_closure.py** | Anchor/bridge candidate detection from findings. |
| **missing_link_engine.py** | Hunt suggestions for missing ANCHOR/BRIDGE roles. |
| **asset_discovery.py** | Collect assets by type; reference extraction from XML/JSON/config. |
| **renderer.py** | Report → HTML. |
| **exporter.py** | JSON→TXT/HTML (render_html expects report dict; current call passes Path – see exporter bug below). |

---

## 2. Critical Findings

### 2.1 CLI flags `-e` and `-O` are not wired to the engine

- **`-e`** (extended surface expansion) and **`-O`** (offensive surface synthesis) are parsed in `cli.py` but **never passed to `run()`**.
- **Impact:** Documented behavior does not occur; extended/offensive modes are no-ops.
- **Fix:** Pass options into `run()` (e.g. `run(args.target, extended=args.e, offensive=args.O)`) and have `build_reasoning()` / harvest phases respect them (e.g. pass `enum` into `expand()` when extended, or enable extra synthesis steps when offensive).

### 2.2 Bare `except` in engine

- **Location:** `engine.py` in `harvest_bundle()` (and similar harvest paths), `except: pass` swallows all exceptions including `KeyboardInterrupt`/`SystemExit`.
- **Fix:** Use `except Exception: pass` (or log and re-raise if appropriate).

### 2.3 Standalone `.js` in directory mode can crash

- **Context:** When there are no `.app` bundles, `harvest_directory_binaries()` is used; `VALID_SUFFIX` includes `.js`. For a `.js` file, `analyze()` → `imports()` → `_inspect_binary()` returns `None` (only Mach-O/ELF/PE handled), and `imports()` raises `RuntimeError("Unsupported or non-binary file")`.
- **Impact:** Scanning a directory that contains only scripts (e.g. some Windows layouts) can crash.
- **Fix:** Either exclude `.js` from `harvest_directory_binaries()` when it’s not an Electron preload context, or extend `static_parser` to return a minimal analysis for non-binary assets (e.g. `{"target": name, "imports": [{"path": name, "binary": "js", "imports": []}], "entropy": 0}`) so `imports()` doesn’t raise for known script types.

### 2.4 Single-file mode: surface format mismatch

- In single-file mode the report builds `surfaces_single = [{"surface": entry["class"], "path": entry["file"]}]`. `entry["class"]` is the full classifier dict `{"surfaces": [...], "exploits": [...]}`, but `synthesize()` expects each `s["surface"]` to be a **string** (e.g. `"electron_preload"`). So `EXPLOIT_FAMILIES.get(cls)` is always `None` and synth indicators are empty for single-file runs.
- **Fix:** Reuse `build_reasoning([entry], extended=..., offensive=...)` for single-file, or map `entry["class"]` to a list of surface records with string `surface` before calling `synthesize()`.

### 2.5 Exporter module signature mismatch

- **exporter.py** `export(json_path, mode)` for `mode == "html"` calls `render_html(json_path)`.
- **renderer.render()** expects a **report dict**, not a `Path`. Passing a Path would cause type errors when the report is indexed.
- **Fix:** Load JSON from `json_path` and call `render(report)`; then write the HTML to a suitable path (e.g. same stem as `json_path` with `.html`), or adjust the export API so the caller passes the report dict and output path.

---

## 3. Performance & Structure

### 3.1 Redundant filesystem walks

- In directory mode with bundles, **discovered assets** are filled in two ways: (1) inside `harvest_bundle()` via `_add_to_discovered_assets()` for each bundle, and (2) `asset_discovery.collect_discovered_assets(base, discovered_assets)` over the whole base.
- So the tree under `base` is walked multiple times (per-bundle `rglob` in harvest + full `rglob` in `collect_discovered_assets`). For large installs this duplicates work.
- **Suggestion:** Either do asset collection in a single pass (e.g. one walk that both feeds harvest and fills `discovered_assets`), or have `collect_discovered_assets` only run when no bundles were scanned (e.g. Windows-only dir) to avoid double walk.

### 3.2 Subprocess usage in static_parser

- Every binary uses `file`, and on macOS `otool -L`, on Linux `ldd`, etc. Many small subprocesses for large targets (e.g. 80 files) add overhead.
- **Suggestions:** (1) Cache `file`/imports per path in a single run. (2) Consider using **lief** (already optional) for Mach-O/ELF/PE where available to avoid subprocess calls. (3) Optionally batch or limit concurrency if introducing parallel analysis.

### 3.3 Constants and limits

- `MAX_FILES = 80`, `MAX_SIZE = 120 * 1024 * 1024`, `DISCOVERED_HTML_MAX = 500`, `MAX_PER_TYPE = 500` are hardcoded. Making these configurable (e.g. env or CLI) would help large engagements and CI without code changes.

---

## 4. Code Quality & Safety

- **Version string:** Repeated as `"Unveil RADAR v0.6.0"` in `cli.py` and README; consider a single source (e.g. `unveil/__init__.py` or `pyproject.toml` version) and import where needed.
- **Error handling:** DMG mount/unmount and ZIP unpacking use broad `except` or ignore errors; consider logging and clearer user messages (e.g. “DMG mount failed: …”).
- **JSON output:** Always emitted to stdout when not using `-q` (pretty-printed). With `-xj`/`-xx` the same content is also written to a file; behavior is consistent but could be documented (e.g. “JSON is always printed unless `-q`; `-xj`/`-xx` additionally write to file”).

---

## 5. Optional Enhancements

- **Daemon:** Currently only exposes `/health`. If the daemon is meant to run scans remotely, add an endpoint that accepts a target path (or upload), calls `run()`, and returns the report (and optionally triggers export).
- **Tests:** No tests visible in the audited tree; adding unit tests for `classifier`, `normalize_surfaces`, and `build_reasoning` would protect refactors and the new `-e`/`-O` behavior.
- **Manifest:** `static_parser.manifest()` is a stub (“not implemented yet”). Either implement (e.g. for APK/PE) or remove from the analysis pipeline if unused.
- **BLADE role in missing_link_engine:** `MISSING_LINK_TEMPLATES` has ANCHOR and BRIDGE only; if BLADE is part of the killchain, consider adding BLADE hunt suggestions when that role is missing.

---

## 6. Summary Table

| Priority | Finding | Status |
|----------|---------|--------|
| High | `-e` / `-O` not passed to engine | **Fixed:** CLI passes to `run()`; `build_reasoning(extended, offensive)`; verdict `hunt_plan` gated by `offensive` |
| High | Bare `except` in harvest | **Fixed:** Replaced with `except Exception` in `harvest_bundle()` |
| Medium | .js in dir mode → RuntimeError | **Fixed:** `static_parser.imports()` returns minimal `script` entry for non-binary files instead of raising |
| Medium | Exporter passes Path to render | **Fixed:** Load JSON, call `render(report)`, write HTML to `.html` file |
| Medium | Single-file mode surface format | Open: `entry["class"]` is dict; synth expects string surface tags |
| Low | Double walk for discovered assets | Open: single-pass or conditional collection |
| Low | Many subprocesses in static_parser | Open: cache and/or use lief |
| Low | Hardcoded limits | Open: CLI or env for MAX_FILES, MAX_SIZE, etc. |

---

*End of audit.*
