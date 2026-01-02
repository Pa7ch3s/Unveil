from unv.classifier import classify
from unv.static_parser import analyze
from unv.surface_expander import expand
from unv.surface_synth import synthesize
from unv.verdict_compiler import compile
from unv.cli_printer import pretty
from unv.cli_printer import pretty
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

VALID_SUFFIX = {".exe", ".bin", ".dylib", ".so"}

def tick(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()

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
        data = {
            "metadata": {"target": target},
            "results": [entry],
            "verdict": verdict,
            "surfaces": [],
            "synth_indicators": [entry]
        }
        return data

    count = 0
    tick(f"[SCAN] {target}")

    for item in base.iterdir():
        if count >= MAX_FILES:
            break

        if item.name in SKIP_DIRS or item.is_symlink():
            continue

        if item.is_file():
            if item.stat().st_size > MAX_SIZE:
                continue
            if item.suffix.lower() in VALID_SUFFIX:
                tick(f"[BIN] {item.name}")
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

        if item.is_dir() and item.suffix.lower() == ".app":
            tick(f"[APP] {item.name}")
            binpath = item / "Contents/MacOS"
            if binpath.exists():
                for f in binpath.iterdir():
                    if f.stat().st_size > MAX_SIZE:
                        continue
                    tick(f"    └─ {f.name}")
                    try:
                        entry = {
                            "file": str(f),
                            "analysis": analyze(str(f))
                        }
                        entry["class"] = classify(entry)
                        results.append(entry)
                        count += 1
                    except:
                        pass
                    if count >= MAX_FILES:
                        break

    tick("[DONE]")

    indicators = []
    for r in results:
        indicators.append({"class": r["class"], "file": r["file"]})

    surfaces = expand(indicators, {})
    synth = synthesize(surfaces)
    verdict = compile(synth, surfaces, {})

    data = {
        "metadata": {"target": target},
        "results": results,
        "verdict": verdict,
        "surfaces": surfaces,
        "synth_indicators": synth
    }

    return data
