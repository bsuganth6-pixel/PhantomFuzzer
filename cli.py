#!/usr/bin/env python3
"""
PhantomFuzzer CLI — Web Application Vulnerability Scanner
═══════════════════════════════════════════════════════════════
USAGE
  python3 cli.py fuzz <url> --param <name> [--category sqli,xss,...]
  python3 cli.py discover <url>              Find forms on a page
  python3 cli.py --help

Only use against applications you own or are explicitly authorized
to test. This tool sends real, active requests to the target.
"""

import os
import sys
import json
import argparse

from modules import fuzzer, form_parser, payloads

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
def _c(code): return code if _COLOR else ""
R=_c("\033[0m"); BOLD=_c("\033[1m"); DIM=_c("\033[2m")
RED=_c("\033[91m"); GRN=_c("\033[92m"); YLW=_c("\033[93m")
CYN=_c("\033[96m"); VIO=_c("\033[95m")

SEP = f"{DIM}{'─'*76}{R}"


def banner():
    print(f"""{CYN}{BOLD}
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
  {DIM}F U Z Z E R  —  Web Application Vulnerability Scanner{R}
  {YLW}Only use against applications you own or are authorized to test.{R}
""")


def err(msg):  print(f"{RED}✗ {msg}{R}", file=sys.stderr)
def ok(msg):   print(f"{GRN}✓ {msg}{R}")
def info(msg): print(f"{CYN}ℹ {msg}{R}")
def warn(msg): print(f"{YLW}⚠ {msg}{R}")


def conf_color(conf):
    return {"high": RED, "medium": YLW, "low": CYN}.get(conf, R)


def print_findings(findings):
    if not findings:
        ok("No vulnerability signals detected.")
        return
    for f in findings:
        c = conf_color(f["confidence"])
        print(f"  {c}[{f['confidence'].upper():<6}]{R} {BOLD}{f['type'].replace('_',' ')}{R} ({f.get('category','')})")
        print(f"  {DIM}{'':<8} {f['evidence']}{R}")
        print(f"  {DIM}{'':<8} payload: {VIO}{f['payload'][:70]!r}{R}")
        print()


def cmd_fuzz(args):
    categories = args.category.split(",") if args.category else list(payloads.CATEGORIES.keys())
    invalid = [c for c in categories if c not in payloads.CATEGORIES]
    if invalid:
        err(f"Unknown categories: {', '.join(invalid)}. Valid: {', '.join(payloads.CATEGORIES.keys())}")
        sys.exit(2)

    if args.delay_ms < 50:
        err("Minimum delay is 50ms — this tool enforces polite rate limits by design.")
        sys.exit(2)

    if not args.json:
        info(f"Fuzzing {args.url} (param: {args.param}, categories: {', '.join(categories)})...")
        if "sqli" in categories or "cmdi" in categories:
            warn("Time-based payloads in this run will each take ~5s if the target is vulnerable — "
                "this can make the session take a while.")

    result = fuzzer.run_fuzz_session(
        args.url, args.param, categories=categories, method=args.method,
        delay_ms=args.delay_ms, max_requests=args.max_requests,
    )

    if args.json:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["total_findings"] == 0 else 1)

    print()
    print(SEP)
    print(f"  {BOLD}SESSION SUMMARY{R}")
    print(SEP)
    print(f"  {DIM}Findings:{R}  {result['total_findings']}")
    print(f"  {DIM}Requests:{R}  {result['total_requests']}")
    print(f"  {DIM}Duration:{R}  {result['elapsed_seconds']}s")
    if result["capped"]:
        warn(f"Hit the request cap ({args.max_requests}) — some payloads may not have been tested.")
    print()

    print(SEP)
    print(f"  {BOLD}BY CATEGORY{R}")
    print(SEP)
    for cat, cat_result in result["results"].items():
        if cat_result.get("error"):
            print(f"  {cat:<12} {RED}{cat_result['error']}{R}")
        else:
            color = RED if cat_result["findings"] else GRN
            print(f"  {cat:<12} {color}{len(cat_result['findings'])}/{cat_result['payloads_tested']} payloads flagged{R}")
    print()

    print(SEP)
    print(f"  {BOLD}FINDINGS{R} ({result['total_findings']})")
    print(SEP)
    print_findings(result["all_findings"])

    if result["total_findings"] > 0:
        warn("Findings indicate signals CONSISTENT WITH a vulnerability — verify manually before treating as confirmed.")

    sys.exit(0 if result["total_findings"] == 0 else 1)


def cmd_discover(args):
    result = form_parser.discover_forms(args.url)
    if args.json:
        print(json.dumps(result, indent=2))
        return

    if not result["success"]:
        err(result["error"]); sys.exit(2)

    print()
    if not result["forms"]:
        info("No forms found on this page.")
        return

    for form in result["forms"]:
        print(f"  {VIO}{form['method']}{R} {form['action']}")
        for field in form["fields"]:
            print(f"    {DIM}-{R} {field['name']} ({field['type']})")
        print()


# ════════════════════════════════════════════════════════════════
#  ARGPARSE
# ════════════════════════════════════════════════════════════════

def build_parser():
    p = argparse.ArgumentParser(
        prog="cli.py", description="PhantomFuzzer — Web Application Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("fuzz", help="Fuzz a target parameter (exit: 0=clean, 1=findings, 2=error)")
    sp.add_argument("url")
    sp.add_argument("--param", required=True, help="Parameter name to fuzz")
    sp.add_argument("--method", choices=["GET", "POST"], default="GET")
    sp.add_argument("--category", default=None,
                    help=f"Comma-separated: {','.join(payloads.CATEGORIES.keys())} (default: all)")
    sp.add_argument("--delay-ms", type=int, default=250, help="Delay between requests (min 50ms)")
    sp.add_argument("--max-requests", type=int, default=500, help="Hard cap on requests this session")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_fuzz)

    sp = sub.add_parser("discover", help="Discover forms on a page")
    sp.add_argument("url")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_discover)

    return p


def main():
    if len(sys.argv) == 1:
        banner()
        build_parser().print_help()
        return
    args = build_parser().parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print(); info("Cancelled.")
        sys.exit(130)


if __name__ == "__main__":
    main()
