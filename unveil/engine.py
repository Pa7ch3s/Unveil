from unveil.classifier import classify
from unveil.static_parser import analyze
from unveil.surface_expander import expand
from unveil.surface_synth import synthesize
from unveil.verdict_compiler import compile
from pathlib import Path
import sys
import tempfile
import subprocess
import shutil
import zipfile

MAX_FILES = 80
MAX_SIZE = 120 * 1024 * 1024

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
            z.extractall(tmp)
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


def collect_discovered_html(root, out_list, max_items=DISCOVERED_HTML_MAX):
    """Collect .html/.htm paths under root for report (openable in browser for attacks/redev/transparency)."""
    root = Path(root)
    if not root.is_dir():
        return
    for item in root.rglob("*"):
        if len(out_list) >= max_items:
            return
        if not item.is_file():
            continue
        if item.suffix.lower() in (".html", ".htm"):
            out_list.append(str(item.resolve()))


def harvest_bundle(bundle, base, results, count_ref, discovered_html=None):
    if discovered_html is None:
        discovered_html = []
    for item in bundle.rglob("*"):
        if count_ref[0] >= MAX_FILES:
            return

        rel = item.relative_to(base)

        if item.is_symlink():
            continue

        name = item.name.lower()

        if name in SKIP_DIRS:
            continue

        # Discovered HTML: list for interactivity (open in browser, redev, attacks)
        if item.is_file() and item.suffix.lower() in (".html", ".htm"):
            if len(discovered_html) < DISCOVERED_HTML_MAX:
                discovered_html.append(str(item.resolve()))
                tick(f"    └─ [html] {rel.name}")
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
        except:
            pass

# ------------------------------------------------------------
# Phase 4 – Reasoning Pipeline
# ------------------------------------------------------------

def build_reasoning(results):
    """
    Bridge classifier output into the reasoning layer.

    `classifier` currently returns a dict:
        {"surfaces": [...], "exploits": [...]}

    The reasoning/expansion layer expects indicator records with a string
    `class` field (e.g. "ELECTRON_PRELOAD_RCE", "QT_PLUGIN_RPATH_HIJACK").

    Here we fan out one indicator per relevant surface / exploit tag so that
    `expand` and `EXPLOIT_FAMILIES` can light up findings and synth indicators.
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
            }:
                codes.add(ex)

        for code in codes:
            indicators.append({"class": code, "file": file_path})

    surfaces = expand(indicators, {})
    findings = normalize_surfaces(surfaces)
    synth = synthesize(surfaces)
    verdict = compile(synth, surfaces, findings)
    return findings, synth, verdict

# ------------------------------------------------------------
# Phase 5 – Main Entry
# ------------------------------------------------------------

def run(target):
    base = Path(target)
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
            tick("[DMG] mount failed")
            return {
                "metadata": {"target": target},
                "results": [],
                "verdict": {"exploitability_band": "UNKNOWN", "missing_roles": ["ANCHOR", "BRIDGE", "BLADE"]},
                "findings": [],
                "surfaces": [],
                "synth_indicators": [],
                "discovered_html": [],
            }
        base = Path(mount_dir)
        unmount_dmg = mount_dir

    unpack_dir = None

    # -------- IPA Mode: unpack and run .app bundle scan on Payload/ --------
    if base.is_file() and base.suffix.lower() == ".ipa" and not unmount_dmg:
        tick(f"[IPA] {base.name}")
        tmp, root = _unpack_zip(base, "Payload")
        if root is None or not root.is_dir():
            tick("[IPA] unpack failed")
            return {
                "metadata": {"target": target},
                "results": [],
                "verdict": {"exploitability_band": "UNKNOWN", "missing_roles": ["ANCHOR", "BRIDGE", "BLADE"]},
                "findings": [],
                "surfaces": [],
                "synth_indicators": [],
                "discovered_html": [],
            }
        base = root
        unpack_dir = tmp

    # -------- APK Mode: unpack and harvest lib/*.so --------
    if base.is_file() and base.suffix.lower() == ".apk" and not unmount_dmg:
        tick(f"[APK] {base.name}")
        tmp, root = _unpack_zip(base, None)
        if root is None or not root.is_dir():
            tick("[APK] unpack failed")
            return {
                "metadata": {"target": target},
                "results": [],
                "verdict": {"exploitability_band": "UNKNOWN", "missing_roles": ["ANCHOR", "BRIDGE", "BLADE"]},
                "findings": [],
                "surfaces": [],
                "synth_indicators": [],
                "discovered_html": [],
            }
        base = root
        unpack_dir = tmp
        tick(f"[SCAN] {target}")
        count_ref = [0]
        harvest_apk(base, results, count_ref)
        discovered_html_apk = []
        collect_discovered_html(base, discovered_html_apk)
        tick("[DONE]")
        findings, synth, verdict = build_reasoning(results)
        if unpack_dir:
            shutil.rmtree(unpack_dir, ignore_errors=True)
        return {
            "metadata": {"target": target},
            "results": results,
            "verdict": verdict,
            "findings": findings,
            "surfaces": findings,
            "synth_indicators": synth,
            "discovered_html": discovered_html_apk,
        }

    # -------- Single File Mode (non-DMG file) --------
    if base.is_file() and not unmount_dmg:
        tick(f"[ANALYZE] {base.name}")
        entry = {
            "file": str(base),
            "analysis": analyze(str(base))
        }
        entry["class"] = classify(entry)
        surfaces_single = [{"surface": entry["class"], "path": entry["file"]}]
        synth = synthesize(surfaces_single)
        verdict = compile(synth, [], [])
        single_discovered = [str(base.resolve())] if base.suffix.lower() in (".html", ".htm") else []
        return {
            "metadata": {"target": target},
            "results": [entry],
            "verdict": verdict,
            "findings": [],
            "surfaces": [],
            "synth_indicators": synth,
            "discovered_html": single_discovered,
        }

    # -------- Directory Mode (or mounted DMG) --------
    tick(f"[SCAN] {target}")
    count_ref = [0]

    bundles = discover_bundles(base)

    # If the target itself is an .app bundle, treat it as a bundle root
    # so `unveil -C /Applications/Foo.app` actually scans that bundle.
    if not bundles and base.is_dir() and base.suffix.lower() == ".app":
        bundles = [base]

    discovered_html = []
    for bundle in bundles:
        if count_ref[0] >= MAX_FILES:
            break

        rel = bundle.relative_to(base)
        tick(f"[APP] {rel}")
        harvest_bundle(bundle, base, results, count_ref, discovered_html)

    # No .app bundles (e.g. Windows app dir): harvest .exe/.dll/.so etc. from the tree
    if not bundles:
        harvest_directory_binaries(base, results, count_ref)
    collect_discovered_html(base, discovered_html)

    # Windows persistence: harvest Tasks/Startup/Run/Scripts artifacts when scanning a directory
    harvest_windows_persistence(base, results, count_ref)

    # -------- Reasoning --------
    tick("[DONE]")
    findings, synth, verdict = build_reasoning(results)

    if unmount_dmg:
        subprocess.run(["hdiutil", "detach", unmount_dmg], capture_output=True)
        shutil.rmtree(unmount_dmg, ignore_errors=True)
    if unpack_dir:
        shutil.rmtree(unpack_dir, ignore_errors=True)

    return {
        "metadata": {"target": target},
        "results": results,
        "verdict": verdict,
        "findings": findings,
        "surfaces": findings,
        "synth_indicators": synth,
        "discovered_html": discovered_html,
    }
