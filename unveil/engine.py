from unveil.classifier import classify
from unveil.static_parser import (
    analyze,
    clear_analysis_cache,
    specifications_for_target,
    interesting_strings,
    build_import_summary,
    build_packed_entropy_list,
)
from unveil.surface_expander import expand
from unveil.surface_synth import synthesize
from unveil.verdict_compiler import compile
from unveil import asset_discovery
from unveil import config as _config
from unveil.electron_info import get_electron_info
from unveil.chainability import build_chainability
from unveil.checklist_scan import run_checklist
from unveil.attack_graph import build_attack_graph
from unveil.missing_link_engine import enrich_hunt_plan_with_matched_paths
from unveil.permission_audit import run_audit as permission_audit
from unveil.cert_audit import run_cert_audit
from unveil.dotnet_audit import run_dotnet_audit
from unveil.cve_lookup import enrich_report_cve_lookup
from unveil.instrumentation_hints import build_instrumentation_hints
from pathlib import Path
import sys
import tempfile
import subprocess
import shutil
import zipfile
import plistlib

MAX_FILES = 80
MAX_SIZE = 120 * 1024 * 1024


def _resolve_limits(max_files=None, max_size_mb=None, max_per_type=None):
    """Apply env/override to module limits for this run."""
    global MAX_FILES, MAX_SIZE
    MAX_FILES = _config.get_max_files(max_files)
    MAX_SIZE = _config.get_max_size_bytes(max_size_mb)
    asset_discovery.MAX_PER_TYPE = _config.get_max_per_type(max_per_type)

SKIP_DIRS = {
    "Xcode.app",
    "Simulator.app",
    "iOS Simulator.app",
    "Developer",
    "Command Line Tools"
}

VALID_SUFFIX = {".exe", ".dll", ".bin", ".dylib", ".so", ".js"}
DISCOVERED_HTML_MAX = 500

SURFACE_POWER = {
    "qt_rpath_plugin_drop": "ANCHOR",
    "preload_write": "ANCHOR",
    "macos_launch_persistence": "ANCHOR",
    "windows_persistence": "ANCHOR",
    "dotnet_managed": "ANCHOR",
    "electron_helper": "BRIDGE",
    "electron_preload": "BLADE"
}

POWER_CONFIDENCE = {
    "ANCHOR": "HIGH",
    "BRIDGE": "MED",
    "BLADE": "HIGH"
}

POWER_CHAIN = {
    "ANCHOR": ["ANCHOR"],
    "BRIDGE": ["BRIDGE"],
    "BLADE": ["BLADE"]
}

def tick(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def _paths_to_watch_from_assets(discovered_assets, results, target):
    """Build sorted list of paths to watch for process monitor correlation (cap 300)."""
    out = set()
    base = Path(target).resolve()
    if base.is_dir():
        out.add(str(base))
    for r in results or []:
        f = r.get("file")
        if f and isinstance(f, str):
            out.add(f)
    for paths in (discovered_assets or {}).values():
        for p in (paths or [])[:50]:
            if p and isinstance(p, str):
                out.add(p)
    return sorted(out)


def _empty_report(target, reason="UNKNOWN", error=None):
    """Return a minimal report dict with all keys present. Use for early exits (DMG/IPA/APK fail)."""
    meta = {"target": target}
    if error is not None:
        meta["error"] = error
    elif reason != "UNKNOWN":
        meta["skip_reason"] = reason
    return {
        "metadata": meta,
        "specifications": {},
        "results": [],
        "verdict": {"exploitability_band": reason, "missing_roles": ["ANCHOR", "BRIDGE", "BLADE"]},
        "findings": [],
        "surfaces": [],
        "synth_indicators": [],
        "discovered_assets": {},
        "discovered_html": [],
        "extracted_refs": [],
        "electron_info": {},
        "chainability": [],
        "checklist_findings": [],
        "attack_graph": {"chains": [], "sendable_urls": []},
        "interesting_strings": [],
        "permission_findings": [],
        "cert_findings": [],
        "dotnet_findings": [],
        "cve_lookup": None,
        "instrumentation_hints": [],
        "paths_to_watch": [],
        "paths_to_watch_note": "",
        "import_summary": {"libraries": [], "per_file_count": 0},
        "packed_entropy": [],
        "non_http_refs": [],
    }


def _build_extended_enum(discovered_assets, results):
    """Build enum dict for expand(): ATS (NSExceptionDomains from plists), helpers (Electron helper/crashpad paths)."""
    enum = {"helpers": [], "ATS": {"NSExceptionDomains": {}}}
    if not results:
        pass
    else:
        for r in results:
            path = (r.get("file") or "").lower()
            if "helper" in path or "crashpad" in path:
                enum["helpers"].append(r.get("file"))
    plist_paths = (discovered_assets or {}).get("plist") or []
    for path in plist_paths[:50]:
        try:
            with open(path, "rb") as f:
                data = plistlib.load(f)
            ats = data.get("NSAppTransportSecurity") or {}
            domains = ats.get("NSExceptionDomains") or {}
            for k, v in domains.items():
                enum["ATS"]["NSExceptionDomains"][k] = v if isinstance(v, dict) else {}
        except Exception:
            pass
    return enum


# ------------------------------------------------------------
# Phase 1 – Normalize Surface Buckets
# ------------------------------------------------------------

def normalize_surfaces(surfaces):
    buckets = {}

    for s in surfaces:
        cls = s.get("surface", "")
        path = s.get("path", "")
        anchor = s.get("reentry", "")
        boundary = s.get("trust_boundary", "")
        impact = s.get("impact", "")

        key = f"{cls}:{anchor}"

        if key not in buckets:
            power = SURFACE_POWER.get(cls, "UNKNOWN")
            buckets[key] = {
                "id": key,
                "type": "surface",
                "class": cls,
                "power": power,
                "chain_hint": POWER_CHAIN.get(power, []),
                "surface": [],
                "anchor": anchor,
                "persistence": False,
                "pivot": False,
                "evidence": set(),
                "confidence": "LOW",
                "count": 0
            }

        b = buckets[key]
        b["surface"].append(path)
        b["count"] += 1

        if "persistent" in impact:
            b["persistence"] = True
        if "lateral" in impact:
            b["pivot"] = True
        if boundary:
            b["evidence"].add(boundary)

    findings = []

    for b in buckets.values():
        density_conf = "LOW"
        if b["persistence"] and b["count"] >= 2:
            density_conf = "HIGH"
        elif b["pivot"] or b["persistence"]:
            density_conf = "MED"

        base_conf = POWER_CONFIDENCE.get(b["power"], "LOW")
        order = {"LOW": 0, "MED": 1, "HIGH": 2}
        b["confidence"] = max(density_conf, base_conf, key=lambda x: order[x])

        b["evidence"] = list(b["evidence"])
        findings.append(b)

    return findings

# ------------------------------------------------------------
# Phase 2 – Bundle Discovery
# ------------------------------------------------------------

def discover_bundles(base):
    bundles = []
    for item in base.iterdir():
        if item.is_dir() and item.suffix.lower() == ".app":
            bundles.append(item)
    return bundles


def _safe_zip_extract(z, dest: Path):
    """Extract zip members into dest; skip any path that would escape dest (zip slip)."""
    dest_resolved = dest.resolve()
    for m in z.namelist():
        if not m or m.startswith("/") or ".." in m:
            continue
        try:
            member_dest = (dest / m).resolve()
            member_dest.relative_to(dest_resolved)
        except (ValueError, OSError):
            continue
        z.extract(m, dest)


def _unpack_zip(path, prefix=None):
    """Unpack a .ipa or .apk (ZIP) to a temp dir. Returns (temp_dir_path, root_for_scan).
    prefix: optional subdir to use as scan root (e.g. 'Payload' for IPA).
    """
    path = Path(path)
    if not path.is_file() or path.suffix.lower() not in (".ipa", ".apk"):
        return None, None
    tmp = tempfile.mkdtemp(prefix="unveil_")
    try:
        with zipfile.ZipFile(path, "r") as z:
            _safe_zip_extract(z, Path(tmp))
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, None
    root = Path(tmp)
    if prefix and (root / prefix).is_dir():
        root = root / prefix
    return tmp, root


# ------------------------------------------------------------
# Phase 3 – Recursive Harvest
# ------------------------------------------------------------

def harvest_apk(unpacked_root, results, count_ref):
    """Harvest native libs (lib/*/*.so) from an unpacked APK and run analyze/classify."""
    lib_dir = Path(unpacked_root) / "lib"
    if not lib_dir.is_dir():
        return
    for item in lib_dir.rglob("*.so"):
        if count_ref[0] >= MAX_FILES:
            return
        if not item.is_file() or item.stat().st_size > MAX_SIZE:
            continue
        tick(f"    └─ {item.relative_to(unpacked_root)}")
        try:
            entry = {
                "file": str(item),
                "analysis": analyze(str(item))
            }
            entry["class"] = classify(entry)
            results.append(entry)
            count_ref[0] += 1
        except Exception:
            pass


# Windows persistence: Scheduled Tasks (.xml), Startup folder, Run/Scripts (.vbs, .bat, .ps1, .cmd)
WINDOWS_PERSISTENCE_EXTS = {".xml", ".vbs", ".bat", ".ps1", ".cmd", ".lnk"}
WINDOWS_PERSISTENCE_PATH_PARTS = ("tasks", "scheduled", "schedule", "startup", "run", "runonce", "winlogon", "scripts", "services")

# Linux persistence: systemd, cron, autostart
LINUX_PERSISTENCE_EXTS = {".service", ".timer", ".desktop"}
LINUX_PERSISTENCE_PATH_PARTS = ("systemd", "cron", "crontab", "autostart", "startup")


def harvest_directory_binaries(base, results, count_ref):
    """When there are no .app bundles (e.g. Windows app dir), harvest .exe/.dll/.so/etc. from the tree."""
    base = Path(base)
    if not base.is_dir():
        return
    for item in base.rglob("*"):
        if count_ref[0] >= MAX_FILES:
            return
        if item.is_symlink() or not item.is_file():
            continue
        if any(skip.lower() in (p.lower() for p in item.parts) for skip in SKIP_DIRS):
            continue
        if item.stat().st_size > MAX_SIZE:
            continue
        if item.suffix.lower() not in VALID_SUFFIX:
            continue
        tick(f"    └─ {item.relative_to(base)}")
        try:
            entry = {
                "file": str(item),
                "analysis": analyze(str(item))
            }
            entry["class"] = classify(entry)
            results.append(entry)
            count_ref[0] += 1
        except Exception:
            pass


def harvest_windows_persistence(base, results, count_ref):
    """Harvest Windows persistence artifacts (Tasks XML, Startup, Run/Scripts) from a directory."""
    base = Path(base)
    if not base.is_dir():
        return
    for item in base.rglob("*"):
        if count_ref[0] >= MAX_FILES:
            return
        if not item.is_file():
            continue
        p = str(item).lower()
        ext = item.suffix.lower()
        # Scheduled Task XML
        if ext == ".xml" and ("task" in p or "schedule" in p):
            pass
        elif ext in WINDOWS_PERSISTENCE_EXTS and any(part in p for part in WINDOWS_PERSISTENCE_PATH_PARTS):
            pass
        else:
            continue
        tick(f"    └─ {item.relative_to(base)}")
        entry = {
            "file": str(item),
            "analysis": {
                "target": item.name,
                "imports": [{"path": item.name, "binary": "config", "imports": []}],
                "entropy": 0.0
            }
        }
        entry["class"] = classify(entry)
        if "windows_persistence" in (entry["class"].get("surfaces") or []):
            results.append(entry)
            count_ref[0] += 1


def harvest_linux_persistence(base, results, count_ref):
    """Harvest Linux persistence artifacts (systemd units, cron, autostart .desktop)."""
    base = Path(base)
    if not base.is_dir():
        return
    for item in base.rglob("*"):
        if count_ref[0] >= MAX_FILES:
            return
        if not item.is_file():
            continue
        p = str(item).lower()
        ext = item.suffix.lower()
        if ext in LINUX_PERSISTENCE_EXTS and any(part in p for part in LINUX_PERSISTENCE_PATH_PARTS):
            pass
        elif ext == ".desktop" and ("autostart" in p or "startup" in p):
            pass
        else:
            continue
        tick(f"    └─ {item.relative_to(base)}")
        entry = {
            "file": str(item),
            "analysis": {
                "target": item.name,
                "imports": [{"path": item.name, "binary": "config", "imports": []}],
                "entropy": 0.0,
            },
        }
        entry["class"] = classify(entry)
        if "linux_persistence" in (entry["class"].get("surfaces") or []):
            results.append(entry)
            count_ref[0] += 1


def _empty_discovered_assets():
    """Return a dict of asset type -> list (empty) for all ASSET_EXTENSIONS."""
    return {t: [] for t in asset_discovery.ASSET_EXTENSIONS}


def collect_discovered_html(root, out_list, max_items=DISCOVERED_HTML_MAX):
    """Collect .html/.htm paths under root. Dedupes by resolved path. Used when not using asset_discovery (e.g. one-off)."""
    root = Path(root)
    if not root.is_dir():
        return
    seen = set()
    for item in root.rglob("*"):
        if len(out_list) >= max_items:
            return
        if not item.is_file():
            continue
        if item.suffix.lower() in (".html", ".htm"):
            try:
                resolved = str(item.resolve())
                if resolved not in seen:
                    seen.add(resolved)
                    out_list.append(resolved)
            except (OSError, RuntimeError):
                pass


def _add_to_discovered_assets(item, discovered_assets):
    """Append resolved path to discovered_assets[type] if type matches, list not full, and path not already present."""
    if not discovered_assets or not item.is_file():
        return
    t = asset_discovery._suffix_to_type(item.suffix)
    if t is None:
        return
    lst = discovered_assets.get(t)
    if lst is None:
        return
    if len(lst) >= asset_discovery.MAX_PER_TYPE:
        return
    try:
        resolved = str(item.resolve())
        if resolved not in lst:
            lst.append(resolved)
    except (OSError, RuntimeError):
        pass


def harvest_bundle(bundle, base, results, count_ref, discovered_assets=None):
    if discovered_assets is None:
        discovered_assets = {}
    for item in bundle.rglob("*"):
        if count_ref[0] >= MAX_FILES:
            return

        rel = item.relative_to(base)

        if item.is_symlink():
            continue

        name = item.name.lower()

        if name in SKIP_DIRS:
            continue

        # Discovered assets by type (html, xml, json, config, script, plist, etc.)
        if item.is_file():
            _add_to_discovered_assets(item, discovered_assets)
            if item.suffix.lower() in (".html", ".htm"):
                tick(f"    └─ [html] {rel.name}")
                continue
            # Skip binary analysis for asset types we never run static analysis on
            t = asset_discovery._suffix_to_type(item.suffix)
            if t in ("xml", "json", "config", "manifest", "policy", "cert", "data"):
                continue

        # Preload blade promotion
        if name == "preload.js":
            tick(f"    └─ {rel.name}")
            results.append({
                "file": str(item),
                "analysis": {
                    "target": "preload.js",
                    "imports": [{"path": "preload.js", "binary": "js", "imports": []}],
                    "entropy": 0.0
                },
                "class": "ELECTRON_PRELOAD_RCE"
            })
            count_ref[0] += 1
            continue

        if not item.is_file():
            continue

        # macOS persistence: only real definitions (LaunchAgents/LaunchDaemons/Login Items, or XPC Info.plist)
        p = str(item).lower()
        if item.suffix.lower() == ".plist":
            is_launch_daemon = "launchagents" in p or "launchdaemons" in p or "loginitems" in p or "login items" in p
            is_xpc_info = (".xpc" in p or "xpcservice" in p) and item.name == "Info.plist"
            if is_launch_daemon or is_xpc_info:
                tick(f"    └─ {rel.name}")
                entry = {
                    "file": str(item),
                    "analysis": {
                        "target": item.name,
                        "imports": [{"path": item.name, "binary": "plist", "imports": []}],
                        "entropy": 0.0
                    }
                }
                entry["class"] = classify(entry)
                results.append(entry)
                count_ref[0] += 1
                continue

        if item.stat().st_size > MAX_SIZE:
            continue

        if item.suffix.lower() not in VALID_SUFFIX:
            continue

        tick(f"    └─ {rel.name}")

        try:
            entry = {
                "file": str(item),
                "analysis": analyze(str(item))
            }
            entry["class"] = classify(entry)
            results.append(entry)
            count_ref[0] += 1
        except Exception:
            pass

# ------------------------------------------------------------
# Phase 4 – Reasoning Pipeline
# ------------------------------------------------------------

def build_reasoning(results, extended=False, offensive=True, discovered_assets=None):
    """
    Bridge classifier output into the reasoning layer.

    `classifier` currently returns a dict:
        {"surfaces": [...], "exploits": [...]}

    The reasoning/expansion layer expects indicator records with a string
    `class` field (e.g. "ELECTRON_PRELOAD_RCE", "QT_PLUGIN_RPATH_HIJACK").

    Here we fan out one indicator per relevant surface / exploit tag so that
    `expand` and `EXPLOIT_FAMILIES` can light up findings and synth indicators.

    extended: when True, pass richer enum (e.g. ATS/helpers) into expand for deeper surface expansion.
    offensive: when True, run full exploit-chain synthesis and hunt plan (default True for -O).
    discovered_assets: optional dict of asset type -> paths; used when extended=True to build enum.
    """
    indicators = []

    for r in results:
        file_path = r.get("file")
        cls_info = r.get("class")

        # Backwards‑compat: old entries used a plain string class
        if not isinstance(cls_info, dict):
            if cls_info:
                indicators.append({"class": cls_info, "file": file_path})
            continue

        surfaces = cls_info.get("surfaces", []) or []
        exploits = cls_info.get("exploits", []) or []

        codes = set()

        # Map surface tags into indicator classes understood by `expand`.
        for surf in surfaces:
            if surf == "qt_rpath_plugin_drop":
                codes.add("QT_PLUGIN_RPATH_HIJACK")
            elif surf == "electron_preload":
                codes.add("ELECTRON_PRELOAD_RCE")
            elif surf == "electron_helper":
                codes.add("HELPER_BRIDGE")
            elif surf == "macos_launch_persistence":
                codes.add("MACOS_LAUNCH_PERSISTENCE")
            elif surf == "windows_persistence":
                codes.add("WINDOWS_PERSISTENCE")
            elif surf == "dotnet_managed":
                codes.add("DOTNET_MANAGED")
            elif surf == "linux_persistence":
                codes.add("LINUX_PERSISTENCE")
            elif surf == "jar_archive":
                codes.add("JAR_ARCHIVE")

        # Exploit tags may also directly correspond to expansion classes.
        for ex in exploits:
            if ex in {
                "ELECTRON_PRELOAD_RCE",
                "QT_PLUGIN_RPATH_HIJACK",
                "HELPER_BRIDGE",
                "electron_asar_preload",
                "electron_helper_ipc",
                "ats_mitm_downgrade",
                "MACOS_LAUNCH_PERSISTENCE",
                "WINDOWS_PERSISTENCE",
                "DOTNET_MANAGED",
                "LINUX_PERSISTENCE",
                "JAR_ARCHIVE",
            }:
                codes.add(ex)

        for code in codes:
            indicators.append({"class": code, "file": file_path})

    enum = _build_extended_enum(discovered_assets, results) if (extended and discovered_assets is not None) else {}
    surfaces = expand(indicators, enum)
    findings = normalize_surfaces(surfaces)
    synth = synthesize(surfaces)
    verdict = compile(synth, surfaces, findings, offensive=offensive)
    return findings, synth, verdict

# ------------------------------------------------------------
# Phase 5 – Main Entry
# ------------------------------------------------------------

def run(
    target,
    extended=False,
    offensive=True,
    max_files=None,
    max_size_mb=None,
    max_per_type=None,
    ref_extract_max_files=None,
    cve_lookup=False,
):
    _resolve_limits(max_files=max_files, max_size_mb=max_size_mb, max_per_type=max_per_type)
    ref_extract_max = _config.get_ref_extract_max_files(ref_extract_max_files)
    clear_analysis_cache()
    base = Path(target).resolve()
    if not base.exists():
        return _empty_report(
            str(target),
            reason="TARGET_NOT_FOUND",
            error="Target path does not exist: " + str(base),
        )
    results = []
    unmount_dmg = None

    # -------- DMG Mode: mount and run directory scan on contents --------
    if base.is_file() and base.suffix.lower() == ".dmg":
        tick(f"[DMG] {base.name}")
        mount_dir = tempfile.mkdtemp(prefix="unveil_dmg_")
        r = subprocess.run(
            ["hdiutil", "attach", str(base), "-nobrowse", "-mountpoint", mount_dir],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0 or not Path(mount_dir).is_dir():
            shutil.rmtree(mount_dir, ignore_errors=True)
            err = (r.stderr or r.stdout or "").strip() or "unknown"
            _config.log("error", "DMG mount failed", target=target, stderr=err)
            tick("[DMG] mount failed")
            return _empty_report(target, reason="DMG_MOUNT_FAILED", error="DMG mount failed: " + err[:200])
        base = Path(mount_dir)
        unmount_dmg = mount_dir

    unpack_dir = None

    # -------- IPA Mode: unpack and run .app bundle scan on Payload/ --------
    if base.is_file() and base.suffix.lower() == ".ipa" and not unmount_dmg:
        tick(f"[IPA] {base.name}")
        tmp, root = _unpack_zip(base, "Payload")
        if root is None or not root.is_dir():
            _config.log("error", "IPA unpack failed", target=target)
            tick("[IPA] unpack failed")
            return _empty_report(target, reason="IPA_UNPACK_FAILED", error="IPA unpack failed")
        base = root
        unpack_dir = tmp

    # -------- APK Mode: unpack and harvest lib/*.so --------
    if base.is_file() and base.suffix.lower() == ".apk" and not unmount_dmg:
        tick(f"[APK] {base.name}")
        tmp, root = _unpack_zip(base, None)
        if root is None or not root.is_dir():
            _config.log("error", "APK unpack failed", target=target)
            tick("[APK] unpack failed")
            return _empty_report(target, reason="APK_UNPACK_FAILED", error="APK unpack failed")
        base = root
        unpack_dir = tmp
        tick(f"[SCAN] {target}")
        count_ref = [0]
        harvest_apk(base, results, count_ref)
        discovered_assets = _empty_discovered_assets()
        asset_discovery.collect_discovered_assets(base, discovered_assets)
        discovered_html_apk = list(discovered_assets.get("html") or [])
        extracted_refs = asset_discovery.run_reference_extraction(
            discovered_assets, max_files_per_type=ref_extract_max
        )
        tick("[DONE]")
        findings, synth, verdict = build_reasoning(
            results, extended=extended, offensive=offensive, discovered_assets=discovered_assets
        )
        if verdict.get("hunt_plan"):
            verdict["hunt_plan"] = enrich_hunt_plan_with_matched_paths(verdict["hunt_plan"], discovered_assets)
        if unpack_dir:
            shutil.rmtree(unpack_dir, ignore_errors=True)
        apk_interesting = []
        total_cap = 2000
        total_n = 0
        for r in results:
            if total_n >= total_cap:
                break
            path = r.get("file")
            if path and isinstance(path, str):
                try:
                    strs = interesting_strings(path, max_per_file=100)
                    if strs:
                        take = strs[: total_cap - total_n]
                        apk_interesting.append({"file": path, "strings": take})
                        total_n += len(take)
                except Exception:
                    pass
        return {
            "metadata": {"target": target},
            "specifications": specifications_for_target(target) or {},
            "results": results,
            "verdict": verdict,
            "findings": findings,
            "surfaces": findings,
            "synth_indicators": synth,
            "discovered_assets": discovered_assets,
            "discovered_html": discovered_html_apk,
            "extracted_refs": extracted_refs,
            "electron_info": get_electron_info(discovered_assets),
            "chainability": build_chainability(extracted_refs, discovered_assets),
            "checklist_findings": run_checklist(discovered_assets),
            "attack_graph": build_attack_graph(verdict, build_chainability(extracted_refs, discovered_assets), extracted_refs, discovered_html_apk),
            "interesting_strings": apk_interesting,
            "permission_findings": [],
            "cert_findings": run_cert_audit(discovered_assets),
            "dotnet_findings": [],
            "instrumentation_hints": build_instrumentation_hints((build_attack_graph(verdict, build_chainability(extracted_refs, discovered_assets), extracted_refs, discovered_html_apk).get("chains") or [])),
            "paths_to_watch": _paths_to_watch_from_assets(discovered_assets, results, target)[:300],
            "paths_to_watch_note": "Run ProcMon (Windows) or fs_usage (macOS) and filter for these paths to correlate static findings with runtime behavior.",
            "import_summary": build_import_summary(results),
            "packed_entropy": build_packed_entropy_list(results),
            "non_http_refs": asset_discovery.collect_non_http_refs(extracted_refs, max_refs=100),
        }

    # -------- JAR/WAR Mode: unpack and report manifest --------
    if base.is_file() and base.suffix.lower() in (".jar", ".war") and not unmount_dmg:
        tick(f"[JAR] {base.name}")
        tmp = tempfile.mkdtemp(prefix="unveil_jar_")
        try:
            with zipfile.ZipFile(base, "r") as z:
                z.extractall(tmp)
            root = Path(tmp)
            manifest_path = root / "META-INF" / "MANIFEST.MF"
            manifest_note = "no META-INF/MANIFEST.MF"
            if manifest_path.is_file():
                try:
                    manifest_note = manifest_path.read_text(encoding="utf-8", errors="ignore")[:2000]
                except Exception:
                    pass
            entry = {
                "file": str(base),
                "analysis": {
                    "target": base.name,
                    "imports": [{"path": base.name, "binary": "jar", "imports": []}],
                    "entropy": 0.0,
                },
                "class": {"surfaces": ["jar_archive"], "exploits": ["JAR_ARCHIVE"]},
            }
            discovered_assets_jar = _empty_discovered_assets()
            for item in root.rglob("*"):
                if item.is_file():
                    _add_to_discovered_assets(item, discovered_assets_jar)
            findings, synth, verdict = build_reasoning(
                [entry], extended=False, offensive=offensive
            )
            extracted_refs_jar = asset_discovery.run_reference_extraction(
                discovered_assets_jar, max_files_per_type=ref_extract_max
            )
            if verdict.get("hunt_plan"):
                verdict["hunt_plan"] = enrich_hunt_plan_with_matched_paths(verdict["hunt_plan"], discovered_assets_jar)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return {
            "metadata": {"target": target},
            "specifications": specifications_for_target(target) or {},
            "results": [entry],
            "verdict": verdict,
            "findings": findings,
            "surfaces": findings,
            "synth_indicators": synth,
            "discovered_assets": discovered_assets_jar,
            "discovered_html": list(discovered_assets_jar.get("html") or []),
            "extracted_refs": extracted_refs_jar,
            "electron_info": {},
            "chainability": build_chainability(extracted_refs_jar, discovered_assets_jar),
            "checklist_findings": run_checklist(discovered_assets_jar),
            "attack_graph": build_attack_graph(verdict, build_chainability(extracted_refs_jar, discovered_assets_jar), extracted_refs_jar, list(discovered_assets_jar.get("html") or [])),
            "interesting_strings": [],
            "permission_findings": permission_audit(target),
            "cert_findings": run_cert_audit(discovered_assets_jar),
            "dotnet_findings": [],
            "instrumentation_hints": [],
            "paths_to_watch": _paths_to_watch_from_assets(discovered_assets_jar, [entry], target)[:300],
            "paths_to_watch_note": "Run ProcMon (Windows) or fs_usage (macOS) and filter for these paths to correlate static findings with runtime behavior.",
            "import_summary": {"libraries": [], "per_file_count": 0},
            "packed_entropy": [],
            "non_http_refs": asset_discovery.collect_non_http_refs(extracted_refs_jar, max_refs=100),
        }

    # -------- Single File Mode (non-DMG file) --------
    if base.is_file() and not unmount_dmg:
        tick(f"[ANALYZE] {base.name}")
        entry = {
            "file": str(base),
            "analysis": analyze(str(base))
        }
        entry["class"] = classify(entry)
        findings, synth, verdict = build_reasoning([entry], extended=False, offensive=offensive)
        discovered_assets = _empty_discovered_assets()
        if base.suffix.lower() in (".html", ".htm"):
            discovered_assets["html"] = [str(base.resolve())]
        for typ, exts in (("json", (".json",)), ("config", (".config", ".conf", ".cfg", ".ini", ".yaml", ".yml")), ("env", (".env", ".env.local"))):
            if base.suffix.lower() in exts:
                discovered_assets[typ] = [str(base.resolve())]
                break
        if any(base.name.endswith(s) for s in (".js", ".ts", ".mjs", ".cjs")):
            discovered_assets["script"] = [str(base.resolve())]
        discovered_html_single = list(discovered_assets.get("html") or [])
        checklist_single = run_checklist(discovered_assets)
        single_interesting = []
        try:
            strs = interesting_strings(str(base), max_per_file=200)
            if strs:
                single_interesting = [{"file": str(base), "strings": strs}]
        except Exception:
            pass
        single_dotnet = run_dotnet_audit([entry]) if (entry.get("analysis") or {}).get("dotnet") else []
        return {
            "metadata": {"target": target},
            "specifications": specifications_for_target(target) or {},
            "results": [entry],
            "verdict": verdict,
            "findings": findings,
            "surfaces": findings,
            "synth_indicators": synth,
            "discovered_assets": discovered_assets,
            "discovered_html": discovered_html_single,
            "extracted_refs": [],
            "electron_info": {},
            "chainability": [],
            "checklist_findings": checklist_single,
            "attack_graph": {"chains": [], "sendable_urls": []},
            "interesting_strings": single_interesting,
            "permission_findings": permission_audit(target),
            "cert_findings": run_cert_audit(discovered_assets),
            "dotnet_findings": single_dotnet,
            "instrumentation_hints": [],
            "paths_to_watch": _paths_to_watch_from_assets(discovered_assets, [entry], target)[:300],
            "paths_to_watch_note": "Run ProcMon (Windows) or fs_usage (macOS) and filter for these paths to correlate static findings with runtime behavior.",
            "import_summary": build_import_summary([entry]),
            "packed_entropy": build_packed_entropy_list([entry]),
            "non_http_refs": [],
        }

    # -------- Directory Mode (or mounted DMG) --------
    tick(f"[SCAN] {target}")
    count_ref = [0]

    bundles = discover_bundles(base)

    # If the target itself is an .app bundle, treat it as a bundle root
    # so `unveil -C /Applications/Foo.app` actually scans that bundle.
    if not bundles and base.is_dir() and base.suffix.lower() == ".app":
        bundles = [base]

    discovered_assets = _empty_discovered_assets()
    for bundle in bundles:
        if count_ref[0] >= MAX_FILES:
            break

        rel = bundle.relative_to(base)
        tick(f"[APP] {rel}")
        harvest_bundle(bundle, base, results, count_ref, discovered_assets)

    # No .app bundles (e.g. Windows app dir): harvest .exe/.dll/.so etc. from the tree
    if not bundles:
        harvest_directory_binaries(base, results, count_ref)
    asset_discovery.collect_discovered_assets(base, discovered_assets)

    # Windows persistence: harvest Tasks/Startup/Run/Scripts artifacts when scanning a directory
    harvest_windows_persistence(base, results, count_ref)
    # Linux persistence: systemd, cron, autostart
    harvest_linux_persistence(base, results, count_ref)

    # -------- Reasoning --------
    tick("[DONE]")
    findings, synth, verdict = build_reasoning(
        results, extended=extended, offensive=offensive, discovered_assets=discovered_assets
    )

    if unmount_dmg:
        subprocess.run(["hdiutil", "detach", unmount_dmg], capture_output=True)
        shutil.rmtree(unmount_dmg, ignore_errors=True)
    if unpack_dir:
        shutil.rmtree(unpack_dir, ignore_errors=True)

    discovered_html = list(discovered_assets.get("html") or [])
    extracted_refs = asset_discovery.run_reference_extraction(
        discovered_assets, max_files_per_type=ref_extract_max
    )
    chainability = build_chainability(extracted_refs, discovered_assets)
    if verdict.get("hunt_plan"):
        verdict["hunt_plan"] = enrich_hunt_plan_with_matched_paths(verdict["hunt_plan"], discovered_assets)

    # P0: .NET assembly audit (name, version, dangerous API hints)
    dotnet_findings_list = run_dotnet_audit(results)

    # P0: Interesting strings from binaries (URLs, IPs, paths, secret-like) — cap total for report size
    interesting_strings_list = []
    total_strings_cap = 2000
    total_count = 0
    for r in results:
        if total_count >= total_strings_cap:
            break
        path = r.get("file")
        if not path or not isinstance(path, str):
            continue
        try:
            strs = interesting_strings(path, max_per_file=100)
            if strs:
                remaining = total_strings_cap - total_count
                take = strs[:remaining]
                interesting_strings_list.append({"file": path, "strings": take})
                total_count += len(take)
        except Exception:
            pass

    attack_graph = build_attack_graph(verdict, chainability, extracted_refs, discovered_html)
    instrumentation_hints_list = build_instrumentation_hints(attack_graph.get("chains") or [])

    # P2: Paths to watch for process monitor correlation (ProcMon / fs_usage)
    paths_to_watch_set = set()
    base_resolved = Path(target).resolve()
    if base_resolved.is_dir():
        paths_to_watch_set.add(str(base_resolved))
    for r in results:
        f = r.get("file")
        if f and isinstance(f, str):
            paths_to_watch_set.add(f)
    for _type, paths in (discovered_assets or {}).items():
        for p in (paths or [])[:50]:
            if p and isinstance(p, str):
                paths_to_watch_set.add(p)
    paths_to_watch_list = _paths_to_watch_from_assets(discovered_assets, results, target)[:300]
    paths_note = "Run ProcMon (Windows) or fs_usage (macOS) and filter for these paths to correlate static findings with runtime behavior."

    report = {
        "metadata": {"target": target},
        "specifications": specifications_for_target(target) or {},
        "results": results,
        "verdict": verdict,
        "findings": findings,
        "surfaces": findings,
        "synth_indicators": synth,
        "discovered_assets": discovered_assets,
        "discovered_html": discovered_html,
        "extracted_refs": extracted_refs,
        "electron_info": get_electron_info(discovered_assets),
        "chainability": chainability,
        "checklist_findings": run_checklist(discovered_assets),
        "attack_graph": attack_graph,
        "interesting_strings": interesting_strings_list,
        "permission_findings": permission_audit(target),
        "cert_findings": run_cert_audit(discovered_assets),
        "dotnet_findings": dotnet_findings_list,
        "instrumentation_hints": instrumentation_hints_list,
        "paths_to_watch": paths_to_watch_list,
        "paths_to_watch_note": paths_note,
        "import_summary": build_import_summary(results),
        "packed_entropy": build_packed_entropy_list(results),
        "non_http_refs": asset_discovery.collect_non_http_refs(extracted_refs, max_refs=100),
    }
    if cve_lookup:
        enrich_report_cve_lookup(report, max_queries=15, max_cves_per_query=5)
    return report