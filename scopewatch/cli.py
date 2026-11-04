"""Command-line interface for scopewatch."""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .core import candidates, crtsh, dedupe, fdns_baseline, provider_subdomains, read_scope, verify_dns, write_json


def parser() -> argparse.ArgumentParser:
    app = argparse.ArgumentParser(prog="scopewatch", description="Authorized, evidence-first external asset-drift auditor")
    app.add_argument("--version", action="version", version=f"scopewatch {__version__}")
    commands = app.add_subparsers(dest="command", required=True)
    discover = commands.add_parser("discover", help="collect in-scope passive evidence and optional candidates")
    discover.add_argument("--scope", required=True, help="JSON scope file with authorization acknowledgement")
    discover.add_argument("--source", action="append", choices=["crt", "securitytrails", "whoisxml"], default=["crt"])
    discover.add_argument("--wordlist", help="optional labels list; output remains candidate until DNS verifies")
    discover.add_argument("--fdns-file", help="optional user-downloaded Rapid7 FDNS CSV or CSV.GZ baseline")
    discover.add_argument("--verify-dns", action="store_true", help="perform DNS resolution only; no port scan, login, brute force or exploit")
    discover.add_argument("--output", default="scopewatch-findings.json")
    return app


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command != "discover":
        return 2
    try:
        scope = read_scope(args.scope)
    except (OSError, ValueError) as exc:
        print(f"scopewatch: {exc}", file=sys.stderr)
        return 2
    findings = []
    for domain in scope["domains"]:
        for source in dict.fromkeys(args.source):
            if source == "crt":
                findings.extend(crtsh(domain))
            elif source == "securitytrails":
                key = os.getenv("SCOPEWATCH_SECURITYTRAILS_API_KEY")
                if not key:
                    print("scopewatch: skipping SecurityTrails (SCOPEWATCH_SECURITYTRAILS_API_KEY not set)", file=sys.stderr)
                else:
                    findings.extend(provider_subdomains(domain, source, key))
            elif source == "whoisxml":
                key = os.getenv("SCOPEWATCH_WHOISXML_API_KEY")
                if not key:
                    print("scopewatch: skipping WhoisXML (SCOPEWATCH_WHOISXML_API_KEY not set)", file=sys.stderr)
                else:
                    findings.extend(provider_subdomains(domain, source, key))
        if args.wordlist:
            findings.extend(candidates(domain, args.wordlist))
        if args.fdns_file:
            findings.extend(fdns_baseline(domain, args.fdns_file))
    if args.verify_dns:
        findings = verify_dns(findings)
    findings = dedupe(findings)
    write_json(findings, args.output)
    counts = {status: sum(item.status == status for item in findings) for status in ("verified", "observed", "historic", "candidate", "source-error")}
    print("scopewatch wrote", args.output, "|", " ".join(f"{name}={count}" for name, count in counts.items() if count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
