import argparse
import json
from pathlib import Path
from unveil.engine import run
from unveil.cli_printer import pretty

FALLBACK_BANNER = """88        88                                    88 88
88        88                                    "" 88
88        88                                       88
88        88 8b,dPPYba,  8b       d8  ,adPPYba, 88 88
88        88 88P'   `"8a `8b     d8' a8P_____88 88 88
88        88 88       88  `8b   d8'  8PP""""""" 88 88
Y8a.    .a8P 88       88   `8b,d8'   "8b,   ,aa 88 88
 `"Y8888Y"'  88       88     "8"      `"Ybbd8"' 88 88

                 UNVEIL — RADAR v0.5.0
"""

def _banner():
    try:
        from importlib.resources import read_text
        return read_text("unveil", "assets/banner.txt")
    except Exception:
        return FALLBACK_BANNER

def main():
    p = argparse.ArgumentParser(
        prog="unveil",
        description="UNVEIL RADAR — Persistent Exploitability Surface Mapper",
        formatter_class=argparse.RawTextHelpFormatter
    )

    p.add_argument("--version", action="version", version="Unveil RADAR v0.5.0")

    p.add_argument("-C", "--target", required=True,
                   help="Target directory or application bundle to analyze")

    p.add_argument("-e", action="store_true",
                   help="Enable extended surface expansion (deep persistence & lateral surfaces)")

    p.add_argument("-O", action="store_true",
                   help="Enable offensive surface synthesis (exploit-chain modeling)")

    p.add_argument("-f", action="store_true",
                   help="Force analysis of unsigned / malformed binaries")

    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress banner and pretty rendering")

    p.add_argument("-xh", metavar="FILE",
                   help="Export pretty rendered report to HTML")

    p.add_argument("-xj", metavar="FILE",
                   help="Export full JSON report (indented)")

    p.add_argument("-xx", metavar="FILE",
                   help="Export compact raw JSON report")

    args = p.parse_args()

    if not args.quiet:
        print(_banner())

    report = run(args.target)

    if not args.quiet:
        pretty(report)

    if args.xh:
        from unveil.renderer import render
        Path(args.xh).write_text(render(report))

    if args.xj:
        Path(args.xj).write_text(json.dumps(report, indent=2))

    if args.xx:
        Path(args.xx).write_text(json.dumps(report))

if __name__ == "__main__":
    main()
