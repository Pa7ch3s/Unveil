# Full audit — CLI, Burp extension, and documentation (2026-02)

## Scope

- **CLI (Unveil core)** — version, docs, consistency, bugs.
- **Burp extension (unveil-burp)** — version, docs, alignment with CLI, bugs.
- **GitHub / documentation** — README, CHANGELOG, USAGE, GitHub repo and Pages.

---

## 1. CLI (Unveil core)

### Version and single source of truth

| Location | Before | After |
|----------|--------|--------|
| `pyproject.toml` | `0.7.0` | ✅ Kept |
| `unveil/cli.py` | Reads via `importlib.metadata.version("unveil")`, fallback `0.7.0` | ✅ Correct |
| `unveil/sarif_export.py` | Hardcoded `"0.7.0"` | ✅ **Fixed:** uses `_UNVEIL_VERSION` from importlib.metadata |
| `unveil/assets/banner.txt` | No version line (version printed by CLI) | ✅ Correct |
| `docs/AUDIT.md` | Mentioned obsolete "v0.6.0" | ✅ **Fixed:** noted as fixed, single source |

### Documentation alignment

- **README.md** — Features (v0.7.0) updated to include checklist scan and dedupe; flag table already had `-xs`, `--baseline`, `--cve`. ✅
- **docs/USAGE.md** — Quick reference lacked `-xs`, `-V`, `--max-*`, `--baseline`, `--cve`; target lacked `.jar`/`.war`. ✅ **Fixed:** added §18 SARIF, §19 baseline; full flag table.
- **CHANGELOG.md** — 0.7.0 now includes checklist and dedupe; added [0.3.0] for Burp (Checklist tab, Target issues, UI dedupe). ✅

### Bugs / consistency

- **docs/AUDIT.md** — Summary table: "Double walk" and "Hardcoded limits" marked **Fixed** (dedupe and CLI/env limits). ✅
- **HTML report (renderer)** — Did not include `checklist_findings` or `env` in asset types. ✅ **Fixed:** checklist section and `env` in discovered-assets list.

### Checklist scan and dedupe (already implemented)

- `checklist_scan.py` — Patterns for secrets/static-analysis no-nos; report key `checklist_findings`.
- `asset_discovery.py` / `engine.py` — Dedupe by path; one entry per file for extracted_refs.

---

## 2. Burp extension (unveil-burp)

### Version

- **build.gradle.kts** — `version = "0.3.0"`. ✅
- **README** — "v0.3.0" throughout; JAR name `unveil-burp-0.3.0.jar`. ✅

### Documentation alignment

- **Results tabs** — README now lists **Checklist** (potential secrets/static-analysis no-nos). ✅
- **Implemented (v0.3.0)** — Added: Checklist tab; Target/Site Map (audit issues); UI dedupe for assets and refs. ✅
- **Forward-thinking** — "Burp Scanner issues" removed (implemented as Target/Site Map); list renumbered. Roadmap updated: "Scanner issues / Target already implemented." ✅

### Consistency with CLI

- Options, limits, baseline, daemon, Export SARIF — All documented and aligned. ✅

---

## 3. GitHub and GitHub Pages

### Repository (github.com/Pa7ch3s/Unveil)

- README, supported formats, features, install, usage, and flag table match local README (v0.7.0, SARIF, baseline, CVE). ✅
- No separate "GitHub Pages" site was reachable at `https://pa7ch3s.github.io/Unveil/` at audit time. Primary documentation is the repo (README, `docs/`, `unveil-burp/README.md`).

### Recommendation

- If you want a dedicated site: enable **GitHub Pages** in repo **Settings → Pages**, source **main** branch, folder **/ (root)** or **/docs** (if you add an `index.html` in `docs/`). Then the site will be at `https://pa7ch3s.github.io/Unveil/`.

---

## 4. Summary of changes made in this audit

| Area | Change |
|------|--------|
| **docs/AUDIT.md** | Version finding → Fixed; Double walk / Hardcoded limits → Fixed. |
| **README.md** | v0.7.0 features: added checklist scan and dedupe. |
| **CHANGELOG.md** | 0.7.0: checklist, dedupe; new [0.3.0] Burp: Checklist tab, Target issues, UI dedupe. |
| **unveil-burp/README.md** | Checklist in tabs; Implemented: Checklist, Target, UI dedupe; Forward-thinking/Roadmap updated. |
| **docs/USAGE.md** | §18 SARIF (-xs), §19 baseline; full flag table including -xs, -V, --max-*, --baseline, --cve; target .jar/.war. |
| **unveil/renderer.py** | Checklist section in HTML report; `env` in discovered-assets types. |
| **unveil/sarif_export.py** | Tool version from importlib.metadata (no hardcoded 0.7.0). |

---

## 5. Version matrix (after audit)

| Component | Version |
|-----------|---------|
| CLI (pyproject.toml, unveil) | 0.7.0 |
| Burp extension (build.gradle.kts, JAR) | 0.3.0 |
| SARIF / CLI banner | Dynamic from package metadata |

All references to 0.6.0 removed; AUDIT and CHANGELOG reflect current behavior and fixes.
