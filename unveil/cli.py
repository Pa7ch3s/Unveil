import argparse
import json
import sys
from pathlib import Path
from unveil.engine import run
from unveil.cli_printer import pretty

try:
    from importlib.metadata import version as _pkg_version
    VERSION = _pkg_version("unveil")
except Exception:
    VERSION = "0.10.2"

BANNER = Path(__file__).resolve().parent / "assets" / "banner.txt"

def main():
    if BANNER.exists():
        print(BANNER.read_text())
        print(f"\n                 UNVEIL — RADAR v{VERSION}\n")

    p = argparse.ArgumentParser(
        prog="unveil",
        description="UNVEIL RADAR — Persistent Exploitability Surface Mapper",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Disclaimer: This tool is for educational purposes and authorized security testing only. Unauthorized use against systems without prior written consent is strictly prohibited. The author accepts no liability for misuse or damage."
    )

    p.add_argument("--version", action="version", version=f"Unveil RADAR v{VERSION}")

    p.add_argument("-C", "--target", required=True,
                   help="Target to analyze: directory or .app for full recon; single file (e.g. .exe, .dll) for one binary; or .dmg, .ipa, .apk, .jar/.war")

    p.add_argument("-e", action="store_true",
                   help="Extended surface expansion (persistence, helpers, ATS). Use with directory/.app; combine with -O for full attack graph.")

    p.add_argument("-O", action="store_true",
                   help="Offensive surface synthesis (exploit-chain modeling and attack graph). Use with -e for best coverage.")

    p.add_argument("-f", action="store_true",
                   help="Force analysis of unsigned / malformed binaries")

    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress banner and pretty rendering")

    p.add_argument("-V", "--verbose", action="store_true",
                   help="Enable structured JSON log to stderr (or set UNVEIL_LOG=1)")

    p.add_argument("--max-files", type=int, metavar="N", default=None,
                   help="Max binaries to analyze (default: 80; env UNVEIL_MAX_FILES)")

    p.add_argument("--max-size-mb", type=int, metavar="MB", default=None,
                   help="Max file size in MB (default: 120; env UNVEIL_MAX_SIZE_MB)")

    p.add_argument("--max-per-type", type=int, metavar="N", default=None,
                   help="Max discovered assets per type (default: 500; env UNVEIL_MAX_PER_TYPE)")

    p.add_argument("-xh", metavar="FILE",
                   help="Export pretty rendered report to HTML")

    p.add_argument("-xj", metavar="FILE",
                   help="Export full JSON report (indented)")

    p.add_argument("-xx", metavar="FILE",
                   help="Export compact raw JSON report")

    p.add_argument("-xs", metavar="FILE",
                   help="Export SARIF 2.1 report to FILE (for CI/IDE)")

    p.add_argument("--baseline", metavar="FILE",
                   help="Baseline report JSON; add diff and baseline_suppressed to output")

    p.add_argument("--cve", action="store_true",
                   help="Add possible_cves (suggested hunt queries from verdict) to report")

    p.add_argument("--cve-lookup", action="store_true",
                   help="Query NVD API for CVEs (set NVD_API_KEY for higher rate limit)")

    args = p.parse_args()

    if args.verbose:
        import os
        os.environ["UNVEIL_LOG"] = "1"

    try:
        report = run(
            args.target,
            extended=args.e,
            offensive=args.O,
            max_files=args.max_files,
            max_size_mb=args.max_size_mb,
            max_per_type=args.max_per_type,
            cve_lookup=getattr(args, "cve_lookup", False),
        )
    except Exception as e:
        err = str(e) or type(e).__name__
        sys.stderr.write("Unveil failed: " + err + "\n")
        if args.verbose:
            raise
        sys.exit(1)

    # Exit non-zero when engine returned an error (e.g. target not found, DMG mount failed)
    if report.get("metadata", {}).get("error"):
        if not args.quiet:
            pretty(report)
        sys.exit(1)

    if getattr(args, "baseline", None):
        try:
            baseline = json.loads(Path(args.baseline).read_text())
            from unveil.report_diff import apply_baseline
            report = apply_baseline(report, baseline)
        except Exception:
            pass

    if getattr(args, "cve", False):
        report["possible_cves"] = (report.get("verdict") or {}).get("hunt_queries") or []
    else:
        report["possible_cves"] = []

    if not args.quiet:
        pretty(report)

    if args.xh:
        from unveil.renderer import render
        Path(args.xh).write_text(render(report))

    if args.xj:
        Path(args.xj).write_text(json.dumps(report, indent=2))

    if args.xx:
        Path(args.xx).write_text(json.dumps(report))

    if getattr(args, "xs", None):
        from unveil.sarif_export import write_sarif
        write_sarif(report, args.xs)

if __name__ == "__main__":
    main()
