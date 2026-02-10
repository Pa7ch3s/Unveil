from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter
import json

ROLES = {"ANCHOR", "BRIDGE", "BLADE"}


def _print_summary(report):
    meta = report.get("metadata", {})
    target = meta.get("target", "<unknown>")

    verdict = report.get("verdict", {}) or {}
    band = verdict.get("exploitability_band", "UNKNOWN")
    completion = verdict.get("chain_completion", 0.0)
    missing = set(verdict.get("missing_roles", []) or [])
    present = sorted(list(ROLES - missing))

    findings = report.get("findings", []) or []
    synth = report.get("synth_indicators", []) or []

    # Infer high-level frameworks from synth classes
    frameworks = set()
    for s in synth:
        cls = (s.get("class") or "").lower()
        if "electron" in cls:
            frameworks.add("Electron")
        if "qt_" in cls or "qt " in cls:
            frameworks.add("Qt")

    print(f"Target: {target}")
    print(f"Exploitability: {band} (chain completion {completion:.2f})")

    if present or missing:
        print(f"Killchain roles: present={','.join(present) or 'none'} "
              f"missing={','.join(sorted(missing)) or 'none'}")

    if frameworks:
        print(f"Frameworks detected: {', '.join(sorted(frameworks))}")

    # Compact surface summary
    if findings:
        by_class = {}
        for f in findings:
            cls = f.get("class", "unknown")
            by_class.setdefault(cls, 0)
            by_class[cls] += f.get("count", 1)
        parts = [f"{cls} x{count}" for cls, count in sorted(by_class.items())]
        print("Surfaces:", ", ".join(parts))

    print("")  # spacer before raw JSON


def pretty(data, quiet=False):
    if quiet:
        return

    # Human-readable summary first (Nmap-style)
    if isinstance(data, dict):
        _print_summary(data)

    try:
        payload = json.dumps(data, indent=2)
    except Exception:
        payload = str(data)

    print(highlight(payload, JsonLexer(), TerminalFormatter()))

