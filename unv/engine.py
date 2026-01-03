from unv.classifier import classify
from unv.static_parser import analyze
from unv.surface_expander import expand
from unv.surface_synth import synthesize
from unv.verdict_compiler import compile
from pathlib import Path
import sys

MAX_FILES = 80
MAX_SIZE = 120 * 1024 * 1024

SKIP_DIRS = {
    "Xcode.app",
    "Simulator.app",
    "iOS Simulator.app",
    "Developer",
    "Command Line Tools"
}

VALID_SUFFIX = {".exe", ".bin", ".dylib", ".so", ".js"}

SURFACE_POWER = {
    "qt_rpath_plugin_drop": "ANCHOR",
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


def run(target):
    base = Path(target)
    results = []

    if base.is_file():
        tick(f"[ANALYZE] {base.name}")
        entry = {
            "file": str(base),
            "analysis": analyze(str(base))
        }
        entry["class"] = classify(entry)
        verdict = compile([entry], [], {})
        return {
            "metadata": {"target": target},
            "results": [entry],
            "verdict": verdict,
            "findings": [],
            "synth_indicators": [entry]
        }

    count = 0
    tick(f"[SCAN] {target}")

    for item in base.rglob("*"):
        if count >= MAX_FILES:
            break

        if item.is_symlink():
            continue

        name = item.name.lower()

        if name in SKIP_DIRS:
            continue

        # ---- UPGRADE 2: Promote preload.js into blade surface ----
        if name == "preload.js":
            results.append({
                "file": str(item),
                "analysis": {
                    "target": "preload.js",
                    "imports": [{"path": "preload.js", "binary": "js", "imports": []}],
                    "entropy": 0.0
                },
                "class": "ELECTRON_PRELOAD_RCE"
            })
            count += 1
            continue

        if not item.is_file():
            continue

        if item.stat().st_size > MAX_SIZE:
            continue

        if item.suffix.lower() not in VALID_SUFFIX:
            continue

        try:
            entry = {
                "file": str(item),
                "analysis": analyze(str(item))
            }
            entry["class"] = classify(entry)
            results.append(entry)
            count += 1
        except:
            pass

    tick("[DONE]")

    indicators = [{"class": r["class"], "file": r["file"]} for r in results]
    surfaces = expand(indicators, {})

    findings = normalize_surfaces(surfaces)
    synth = synthesize(surfaces)
    verdict = compile(synth, surfaces, findings)

    return {
        "metadata": {"target": target},
        "results": results,
        "verdict": verdict,
        "findings": findings,
        "synth_indicators": synth
    }
