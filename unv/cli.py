from pathlib import Path

print((Path(__file__).resolve().parent / "assets" / "banner.txt").read_text())


import argparse
import json
from pathlib import Path
from unv.engine import run

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-C", "--target", required=True)
    p.add_argument("-e", action="store_true")
    p.add_argument("-O", action="store_true")
    p.add_argument("-f", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-xh", metavar="FILE")
    p.add_argument("-xj", metavar="FILE")
    p.add_argument("-xx", metavar="FILE")
    args = p.parse_args()

    report = run(args.target)

    base = f"unveil-{Path(args.target).name}.json"

    if not args.quiet:
        print(json.dumps(report, indent=2))

    if args.xh:
        from unv.renderer import render
        Path(args.xh).write_text(render(report))

    if args.xj:
        Path(args.xj).write_text(json.dumps(report, indent=2))

    if args.xx:
        Path(args.xx).write_text(json.dumps(report))
