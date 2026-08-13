#!/usr/bin/env python3
"""Shared vocabulary gate (#733, #734).

Some concepts are defined once or they drift. "Is this address local" had five
implementations that disagreed about link-local and about null; "how big is this in
bytes" had nine, two of which rendered "1.0 undefined" past their last unit. Each was
individually reasonable, and nothing compared them.

You cannot mechanically detect "these two functions mean the same thing". But these
concepts are built from a small closed vocabulary of magic literals, and *that* is
checkable: the rule is not "do not duplicate logic", it is "these literals live in one
file". Two rounds of manual searching missed the two formatters named formatFileSize
rather than formatBytes; this check found them immediately.

EXEMPTIONS MAY ONLY SHRINK. Each entry is a known duplicate with an issue attached, not
a permanent carve-out. Adding one is how this check stops working.

Usage: python3 scripts/check_shared_vocabulary.py [--root .]
Exit 0 clean, 1 on a violation.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# --- rules -----------------------------------------------------------------

RULES = [
    {
        "name": "private/link-local address ranges",
        "why": "five implementations disagreed about fe80::/10 and about null (#694, #733)",
        "owner": "backend common/net/IpLocality.java, frontend utils/ipClassification.ts",
        # A *prefix constant* — the literal ends at the dot, which is what a range test
        # looks like. A sample address such as '192.168.1.42' keeps going and is not a
        # definition of anything.
        "pattern": re.compile(
            r"""(?x)
            (?: ["'] (?: 10\. | 192\.168\. | 172\.(?:16|31)\. | 127\. | 169\.254\. ) ["'] )
            | (?: ["'] (?: fe80 | fc00 | fd00 ) [:.]? ["'] )
            | (?: 10\\\. \s*\| | 192\\\.168 | 169\\\.254 )   # the same list inside a regex literal
            """
        ),
        "owners": {
            "backend/src/main/java/com/tracepcap/common/net/IpLocality.java",
            "frontend/src/utils/ipClassification.ts",
        },
        "exempt": {
            # NEVER_CLUSTER_PREFIXES — a genuinely different concept (loopback,
            # link-local and multicast are not clusterable) built from the same
            # vocabulary. Candidate for the locality slice; not a copy of it.
            "frontend/src/features/network/services/clusterService.ts",
        },
    },
    {
        "name": "byte-size unit ladder",
        "why": "nine implementations, two of which rendered '1.0 undefined' past GB (#733)",
        "owner": "frontend utils/formatters",
        # Two adjacent rungs, not one unit: 'GB' alone is also a country code, and
        # matching it flagged a country-code map on the first run.
        "pattern": re.compile(r"""["']KB["']\s*,\s*["']MB["']"""),
        "owners": {"frontend/src/utils/formatters/index.ts"},
        "exempt": set(),
    },
]

SCAN_DIRS = ["backend/src/main/java", "frontend/src"]
SCAN_SUFFIXES = {".java", ".ts", ".tsx"}

# Comments carry these literals as examples ("e.g. 10.0.1.0/24") and are not definitions.
COMMENT = re.compile(r"^\s*(//|/\*|\*|#)")


def scan(root: Path) -> list[str]:
    failures = []
    for rule in RULES:
        for scan_dir in SCAN_DIRS:
            base = root / scan_dir
            if not base.exists():
                continue
            for path in sorted(base.rglob("*")):
                if path.suffix not in SCAN_SUFFIXES or not path.is_file():
                    continue
                rel = path.relative_to(root).as_posix()
                if "__tests__" in rel or rel.endswith("Test.java") or ".test." in rel:
                    continue
                if rel in rule["owners"] or rel in rule["exempt"]:
                    continue
                try:
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                for n, line in enumerate(lines, 1):
                    if COMMENT.match(line):
                        continue
                    if rule["pattern"].search(line):
                        failures.append(
                            f"{rel}:{n}: {rule['name']} outside {rule['owner']}\n"
                            f"    {line.strip()[:100]}\n"
                            f"    why this is gated: {rule['why']}"
                        )
    return failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    args = ap.parse_args()
    root = Path(args.root).resolve()

    failures = scan(root)
    if failures:
        print("Shared vocabulary defined outside its owning module:\n")
        for f in failures:
            print(f"  {f}\n")
        print(
            "Depend on the owning module instead of redefining the concept. If the\n"
            "concept genuinely differs, say so at the call site and name it for the\n"
            "question it answers, not the shape it tests."
        )
        return 1

    exempt = sum(len(r["exempt"]) for r in RULES)
    print(f"Shared vocabulary OK ({exempt} exemption(s) outstanding — these may only shrink).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
