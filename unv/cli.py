#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path
from importlib import resources
from importlib.metadata import version as pkg_version

from unv import static_parser


def get_version():
    try:
        return pkg_version("unv")
    except Exception:
        return "unknown"


def print_banner():
    try:
        banner = resources.files("unv").joinpath("Unveil_banner.txt").read_text()
        print(banner.rstrip())
    except Exception:
        pass


def cmd_scan(args):
    result = static_parser.analyze(args.target)
    if args.pretty:
        import json
        print(json.dumps(result, indent=2))
    else:
        print(result)


def cmd_strings(args):
    static_parser.strings(args.target)


def cmd_imports(args):
    static_parser.imports(args.target)


def cmd_entropy(args):
    static_parser.entropy(args.target)


def cmd_manifest(args):
    static_parser.manifest(args.target)


def cmd_tools(args):
    static_parser.tools()


def cmd_manual(args):
    static_parser.manual()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="unv",
        description="unv — Unveiling thick-client execution surfaces",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"unv {get_version()}",
    )

    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("scan", help="Scan a file and output JSON")
    p.add_argument("target")
    p.add_argument("--pretty", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("strings", help="Extract printable strings")
    p.add_argument("target")
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("imports", help="List imported libraries / symbols")
    p.add_argument("target")
    p.set_defaults(func=cmd_imports)

    p = sub.add_parser("entropy", help="Compute file entropy")
    p.add_argument("target")
    p.set_defaults(func=cmd_entropy)

    p = sub.add_parser("manifest", help="Dump AndroidManifest / Info.plist")
    p.add_argument("target")
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("tools", help="Show available analysis modules")
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("manual", help="Show unv manual")
    p.set_defaults(func=cmd_manual)

    return parser


def main():
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
