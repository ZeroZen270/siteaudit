"""siteaudit — command-line website auditing for freelancers and small agencies.

Usage:
    siteaudit example.com
    siteaudit example.com --json
    siteaudit example.com --timeout 20
"""
from __future__ import annotations

import argparse
import json
import sys

from .core import audit_domain


def format_human(audit) -> str:
    lines = [
        f"Domain : {audit.domain}",
        f"URL    : {audit.url}",
        f"Score  : {audit.score} (higher = more fixable issues)",
        "",
    ]
    notes = audit.notes
    if "status" in notes:
        lines.append(f"HTTP status : {notes['status']} "
                     f"({notes.get('latency_s', '?')}s)")
    if "final_url" in notes and notes["final_url"] != audit.url:
        lines.append(f"Final URL   : {notes['final_url']}")
    if "cert_days_left" in notes:
        lines.append(f"TLS expires : in {notes['cert_days_left']} days")
    if "error" in notes:
        lines.append(f"Error       : {notes['error']}")
    lines.append("")
    if audit.issues:
        from .core import ISSUE_LABELS
        lines.append("Issues found:")
        for issue in audit.issues:
            lines.append(f"  • {ISSUE_LABELS.get(issue, issue)}")
    else:
        lines.append("No issues found — site looks healthy.")
    if audit.emails:
        lines.append("")
        lines.append("Public contact emails:")
        for e in audit.emails:
            lines.append(f"  • {e}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="siteaudit",
        description="Audit a website for fixable technical issues "
                    "(measured live, nothing invented).")
    parser.add_argument("domain", help="domain to audit, e.g. example.com")
    parser.add_argument("--json", action="store_true",
                        help="emit the full audit as JSON")
    parser.add_argument("--timeout", type=int, default=12,
                        help="per-request timeout in seconds (default 12)")
    args = parser.parse_args(argv)
    try:
        audit = audit_domain(args.domain, timeout=args.timeout)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(audit.to_dict(), indent=2))
    else:
        print(format_human(audit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
