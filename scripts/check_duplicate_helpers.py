#!/usr/bin/env python3
"""Duplicate helper gate (#1342).

The Shared Vocabulary check (check_shared_vocabulary.py) catches a shared concept's
*literals* copied into a new file. It can't catch a copy written with different literals,
or a helper that wraps the concept under a familiar name: five "is this address local"
helpers, seven byte formatters and four formatDuration functions all got past it (#694,
#1339, #1340, #1341). They had one thing in common: the same few names, defined privately
in file after file, where the next author couldn't see the last one.

This lists every helper whose name belongs to a shared concept (formatting, plurals,
percentages, address classification, CIDR normalisation, severity styling) and is defined
in more than one file. Today's duplicates are a baseline (scripts/duplicate_helpers_baseline.txt)
that MAY ONLY SHRINK:

  - a new name defined twice, or a known name in a new file, fails: use the shared one
    (see "Shared Concepts" in CLAUDE.md), or name yours for the question it answers;
  - a baseline entry that's no longer duplicated also fails, so the baseline is shrunk in
    the same PR that fixes it.

A local variable (`const pct = a / b`) isn't a definition; only functions are counted.

Usage: python3 scripts/check_duplicate_helpers.py [--root .] [--print-baseline]
Exit 0 clean, 1 on a violation.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

# Names that mean a shared concept. Kept narrow on purpose: `build` or `toDto` defined twice
# is normal; `formatBytes` defined twice is the bug this exists for.
CONCEPT = re.compile(
    r"""(?x)^(
        format[A-Z]\w* | humani[sz]e\w* | human | plural\w* | pct | percent\w* |
        bytes | megabytes | fmtBytes | duration | span |
        is(?:Private|Internal|Local|Rfc1918|Public|External|HostAddress|Unspecified|Broadcast|Multicast|Special)\w* |
        normali[sz]eCidr | severity\w*
    )$"""
)

# A Java method declaration: modifiers, a return type, the name, an open paren, and a body
# (not a call or an abstract signature).
JAVA_DEF = re.compile(
    r"""^\s*(?:(?:public|protected|private|static|final|synchronized)\s+)+[\w<>\[\],.? ]+?\s+(\w+)\s*\([^;]*$"""
)
# A TypeScript function: `function name(`, `const name = (…) =>`, `const name = function`.
TS_DEF = re.compile(
    r"""^\s*(?:export\s+)?(?:(?:async\s+)?function\s+(\w+)\s*[<(]"""
    r"""|(?:const|let)\s+(\w+)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*(?::\s*[^=]+)?=>"""
    r"""|(?:const|let)\s+(\w+)\s*(?::[^=]+)?=\s*(?:async\s*)?\(\s*$"""  # parameters on the next lines
    r"""|(?:const|let)\s+(\w+)\s*=\s*function\b)"""
)

# The shared definitions (CLAUDE.md, "Shared Concepts"): a copy elsewhere is the finding, not
# the owner it copies.
OWNERS = {
    "backend/src/main/java/com/tracepcap/common/text/Humanize.java",
    "frontend/src/utils/formatters/index.ts",
    "frontend/src/utils/ipClassification.ts",
    "frontend/src/utils/severityColors.ts",
}

SOURCES = [("backend/src/main/java", {".java"}), ("frontend/src", {".ts", ".tsx"})]
BASELINE = "scripts/duplicate_helpers_baseline.txt"


def is_test(rel: str) -> bool:
    return "__tests__" in rel or rel.endswith("Test.java") or ".test." in rel or "/generated/" in rel


def definitions(root: Path) -> dict[str, set[str]]:
    """Concept-named helpers, keyed "java:name" or "ts:name": the backend and the frontend each
    own one of a concept (Humanize and utils/formatters), so a name is compared within its side."""
    out: dict[str, set[str]] = defaultdict(set)
    for base, suffixes in SOURCES:
        for path in sorted((root / base).rglob("*")):
            if path.suffix not in suffixes or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if is_test(rel):
                continue
            pattern = JAVA_DEF if path.suffix == ".java" else TS_DEF
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                m = pattern.match(line)
                if not m:
                    continue
                name = next(g for g in m.groups() if g)
                if CONCEPT.match(name):
                    out[("java:" if path.suffix == ".java" else "ts:") + name].add(rel)
    return out


def duplicates(root: Path) -> dict[str, set[str]]:
    return {n: files for n, files in definitions(root).items() if len(files) > 1}


def read_baseline(root: Path) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    path = root / BASELINE
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, rel = line.split(None, 1)  # name is "java:plural", "ts:formatDuration"
        out[name].add(rel.strip())
    return out


def render(dups: dict[str, set[str]]) -> str:
    lines = [
        "# Known duplicate helpers: <name> <file>. MAY ONLY SHRINK (#1342).",
        "# Fix one by routing it to the shared definition, then delete its lines here.",
    ]
    for name in sorted(dups):
        for rel in sorted(dups[name]):
            lines.append(f"{name} {rel}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--print-baseline", action="store_true",
                    help="print today's duplicates in baseline format (to shrink it, not grow it)")
    args = ap.parse_args()
    root = Path(args.root).resolve()

    dups = duplicates(root)
    if args.print_baseline:
        sys.stdout.write(render(dups))
        return 0

    baseline = read_baseline(root)
    new, gone = [], []
    for name, files in sorted(dups.items()):
        for rel in sorted(files - baseline.get(name, set()) - OWNERS):
            others = ", ".join(sorted(files - {rel}))
            bare = name.split(":", 1)[1]
            new.append(f"{rel}: defines {bare}(), which {others} already define{'s' if len(files) == 2 else ''}")
    for name, files in sorted(baseline.items()):
        for rel in sorted(files - dups.get(name, set())):
            gone.append(f"{name} {rel}")

    if new:
        print("A shared concept's helper is defined again:\n")
        for n in new:
            print(f"  {n}")
        print("\nCall the shared one (CLAUDE.md, \"Shared Concepts\"). If yours means something"
              "\nelse, name it for the question it answers, not the shape of its output.\n")
    if gone:
        print("Fixed, so drop these lines from " + BASELINE + " (it may only shrink):\n")
        for g in gone:
            print(f"  {g}")
        print()
    if new or gone:
        return 1
    count = sum(len(f) for f in baseline.values())
    print(f"Duplicate helpers OK ({count} baseline line(s) outstanding, these may only shrink).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
