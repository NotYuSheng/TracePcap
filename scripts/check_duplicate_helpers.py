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
        (?:normali[sz]e|valid|validate|parse|canonical)Cidr\w* | severity\w*
    )$"""
)

# A Java method declaration: modifiers, a return type, the name, an open paren, and a body
# (not a call or an abstract signature).
JAVA_DEF = re.compile(
    r"""^\s*(?:(?:public|protected|private|static|final|synchronized|default|@\w+(?:\([^)]*\))?)\s+)*"""
    r"""(?!return\b|new\b|else\b|throw\b)[\w<>\[\],.?]+(?:\s*<[^>]*>)?\s+(\w+)\s*\([^;]*$"""
)
JAVA_KEYWORDS = {"if", "for", "while", "switch", "catch", "synchronized", "return", "new"}
# A TypeScript function: `function name(`, `const name = (…) =>`, `const name = function`.
TS_DEF = re.compile(
    r"""^\s*(?:export\s+(?:default\s+)?)?(?:(?:async\s+)?function\*?\s+(\w+)\s*[<(]"""
    r"""|(?:const|let)\s+(\w+)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:<[^>]*>\s*)?(?:\(.*\)|\w+)\s*(?::\s*[^=]+)?=>"""
    r"""|(?:const|let)\s+(\w+)\s*=\s*function\b"""
    # a class or object-literal method: `formatBytes(n: number): string {`
    r"""|(?:(?:public|private|protected|static|async|readonly)\s+)*(\w+)\s*(?:<[^>]*>)?\([^)]*\)\s*(?::\s*[^{=]+)?\{\s*$)"""
)
# An arrow whose parameters run over several lines: the name here, `) =>` on a later line.
TS_ARROW_START = re.compile(r"""^\s*(?:export\s+)?(?:const|let)\s+(\w+)\s*(?::[^=]+)?=\s*(?:async\s*)?\(\s*$""")
TS_ARROW_END = re.compile(r"""^[^;]*\)\s*(?::\s*[^=]+)?=>""")
TS_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "constructor"}

# The shared definitions (CLAUDE.md, "Shared Concepts"): a copy elsewhere is the finding, not
# the owner it copies.
OWNERS = {
    "backend/src/main/java/com/tracepcap/common/text/Humanize.java",
    "backend/src/main/java/com/tracepcap/common/net/IpLocality.java",
    "backend/src/main/java/com/tracepcap/common/net/LocalityRules.java",
    "backend/src/main/java/com/tracepcap/common/net/LocalityPolicy.java",
    "frontend/src/utils/formatters/index.ts",
    "frontend/src/utils/ipClassification.ts",
    "frontend/src/utils/severityColors.ts",
}

SOURCES = [("backend/src/main/java", {".java"}), ("frontend/src", {".ts", ".tsx"})]
BASELINE = "scripts/duplicate_helpers_baseline.txt"


def is_test(rel: str) -> bool:
    """Tests, test support, mocks, stories and generated code define helpers of their own."""
    return (rel.endswith("Test.java") or "/generated/" in rel
            or any(m in rel for m in ("__tests__", ".test.", ".spec.", "__mocks__", ".stories.", "/test/")))


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
            java = path.suffix == ".java"
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            for n, line in enumerate(lines):
                name = None
                if java:
                    m = JAVA_DEF.match(line)
                    # An @Override implements a shared interface (LocalityRules.isLocal): the entry
                    # point working as designed, not a copy of it.
                    if m and m.group(1) not in JAVA_KEYWORDS and not overridden(lines, n):
                        name = m.group(1)
                else:
                    m = TS_DEF.match(line)
                    if m:
                        name = next(g for g in m.groups() if g)
                        if name in TS_KEYWORDS:
                            name = None
                    else:
                        m = TS_ARROW_START.match(line)
                        if m and any(TS_ARROW_END.match(l) for l in lines[n + 1:n + 6]):
                            name = m.group(1)
                if name and CONCEPT.match(name):
                    out[("java:" if java else "ts:") + name].add(rel)
    return out


def overridden(lines: list[str], n: int) -> bool:
    """`@Override` on this line or the lines just above it."""
    return any("@Override" in l for l in lines[max(0, n - 3):n + 1])


def duplicates(root: Path) -> dict[str, set[str]]:
    return {n: files for n, files in definitions(root).items() if len(files) > 1}


def read_baseline(root: Path) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    path = root / BASELINE
    if not path.exists():
        return out
    for n, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)  # "java:plural <file>", "ts:formatDuration <file>"
        if len(parts) != 2 or ":" not in parts[0]:
            raise SystemExit(f"{BASELINE}:{n}: expected '<java|ts>:<name> <file>', got {line!r}")
        out[parts[0]].add(parts[1].strip())
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
