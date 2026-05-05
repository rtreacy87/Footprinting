#!/usr/bin/env python3
"""SMTP footprinting lab solver.

Uses the smtp_recon package for full recon, then surfaces the key HTB answers:
  - SMTP banner
  - Discovered usernames

Usage:
    python smtp_footprint_solver.py --target 10.129.42.195
    python smtp_footprint_solver.py --target 10.129.42.195 --domain inlanefreight.htb --wordlist ./footprinting-wordlist.txt
    python smtp_footprint_solver.py --target 10.129.42.195 --verbose
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from smtp_recon import SmtpReconConfig, SmtpOrchestrator

DEFAULT_TARGET = "10.129.42.195"
DEFAULT_WORDLIST = "./footprinting-wordlist.txt"


def _confirmed_users(output_dir: Path, target: str) -> list[str]:
    """Read confirmed users from all three enumeration method outputs."""
    confirmed: list[str] = []
    seen: set[str] = set()

    for fname in ("vrfy_users.json", "expn_users.json", "rcpt_to_users.json"):
        path = output_dir / target / "identity_enumeration" / fname
        if not path.exists():
            continue
        try:
            records = json.loads(path.read_text(encoding="utf-8"))
            for r in records:
                if r.get("status") == "confirmed":
                    u = r.get("username", "")
                    if u and u not in seen:
                        seen.add(u)
                        confirmed.append(u)
        except Exception:
            pass

    return confirmed


def _banner(output_dir: Path, target: str) -> str:
    """Read the captured banner from normalized output or raw session files."""
    # Primary: normalized/banners.txt written by banner_grab check
    banners_path = output_dir / target / "normalized" / "banners.txt"
    if banners_path.exists():
        first_line = banners_path.read_text(encoding="utf-8").splitlines()[0].strip()
        if first_line:
            return first_line

    # Fallback: raw banner session files (banner_25.txt, banner_587.txt, etc.)
    sessions_dir = output_dir / target / "raw" / "manual_sessions"
    if sessions_dir.exists():
        for banner_file in sorted(sessions_dir.glob("banner_*.txt")):
            for line in banner_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("220 "):
                    return line.strip()

    # Fallback: EHLO session
    ehlo_path = sessions_dir / "ehlo_session.txt" if sessions_dir.exists() else None
    if ehlo_path and ehlo_path.exists():
        for line in ehlo_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("220 "):
                return line.strip()

    return "NOT_FOUND"


def _choose_primary(users: list[str]) -> str:
    if not users:
        return "NOT_FOUND"
    for u in users:
        if u.lower() not in {"postmaster", "root", "mailer-daemon"}:
            return u
    return users[0]


def solve(args: argparse.Namespace) -> int:
    wordlist = args.wordlist if Path(args.wordlist).exists() else None
    if not wordlist:
        print(f"[!] Wordlist not found at {args.wordlist}, using built-in defaults", file=sys.stderr)

    config = SmtpReconConfig(
        target=args.target,
        domain=args.domain,
        ports=list(map(int, args.ports.split(","))) if args.ports else [25, 465, 587, 2525],
        wordlist=wordlist,
        from_address=args.from_address,
        to_address=args.to_address,
        safe_mode=not args.no_safe_mode,
        skip_relay=args.skip_relay,
        skip_spoofing=args.skip_spoofing,
        skip_user_enum=args.skip_user_enum,
        timeout=args.timeout,
        output_root=args.output,
        verbose=args.verbose,
    )

    print(f"\n=== SMTP Lab Solver — target {args.target} ===\n", file=sys.stderr)

    orchestrator = SmtpOrchestrator(config)
    results = orchestrator.run()

    output_dir = Path(args.output)
    banner = _banner(output_dir, args.target)
    users = _confirmed_users(output_dir, args.target)
    primary = _choose_primary(users)

    print(f"\n{'='*50}")
    print(f"SMTP banner:              {banner}")
    print(f"Primary username:         {primary}")
    print(f"All confirmed usernames:  {', '.join(users) if users else 'NONE'}")
    print(f"Output directory:         {output_dir / args.target}")
    print(f"{'='*50}\n")

    failed = [r for r in results if r.status == "failed"]
    if failed:
        print(f"[!] {len(failed)} check(s) failed:", file=sys.stderr)
        for r in failed:
            print(f"    - {r.name}: {r.summary}", file=sys.stderr)

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SMTP footprinting lab solver",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--target", default=DEFAULT_TARGET,
        help="Target IP or hostname",
    )
    parser.add_argument(
        "--domain", default="",
        help="Known target domain (e.g. inlanefreight.htb)",
    )
    parser.add_argument(
        "--ports", default=None,
        help="Comma-separated port list (e.g. 25,587). Default: 25,465,587,2525",
    )
    parser.add_argument(
        "--wordlist", default=DEFAULT_WORDLIST,
        help="Username wordlist path",
    )
    parser.add_argument(
        "--from-address", default="test@test.local",
        help="Sender address for relay/spoofing tests",
    )
    parser.add_argument(
        "--to-address", default="test@test.local",
        help="Recipient address for relay/spoofing tests",
    )
    parser.add_argument(
        "--no-safe-mode", action="store_true",
        help="Disable safe mode (allows message submission in relay/spoofing tests)",
    )
    parser.add_argument(
        "--skip-relay", action="store_true",
        help="Skip open relay tests",
    )
    parser.add_argument(
        "--skip-spoofing", action="store_true",
        help="Skip spoofing tests",
    )
    parser.add_argument(
        "--skip-user-enum", action="store_true",
        help="Skip user enumeration",
    )
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="Network timeout in seconds",
    )
    parser.add_argument(
        "--output", default="smtp_recon",
        help="Output root directory",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose logging",
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(solve(parse_args()))
