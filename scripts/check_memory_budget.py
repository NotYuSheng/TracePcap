#!/usr/bin/env python3
"""The accepted upload size must fit in the heap that has to parse it (#779).

Stage 2 holds the whole capture in memory: every conversation, every packet, payloads included,
released only during the database insert in stage 6. So the largest file we accept is bounded by
the JVM heap, and those two numbers are derived separately —

    docker-entrypoint.sh:  JVM heap    = APP_MEMORY_MB * JVM_HEAP_PERCENT / 100
    docker-entrypoint.sh:  upload cap  = APP_MEMORY_MB * UPLOAD_PERCENT   / 100

#92 set the upload cap at 25% when the heap was 75% — a file could be at most a third of the heap.
#586 lowered the heap to 50% to make room for native subprocesses and did not revisit the upload
cap, so the margin silently fell from 3x to 2x. A 468 MB capture was then accepted and died of
OutOfMemoryError 25 minutes into parsing.

Nothing connected the two numbers, so nothing noticed. This does.

Usage: python3 scripts/check_memory_budget.py
Exit 0 clean, 1 on a violation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ENTRYPOINT = Path("backend/docker-entrypoint.sh")
FILE_SERVICE = Path("backend/src/main/java/com/tracepcap/file/service/FileServiceImpl.java")

# A capture must be at most this fraction of the heap. From #92's original design: 25% upload
# against a 75% heap. It is a headroom rule, not a measurement — the parser's real multiplier
# depends on packet size and payload retention — but it is the ratio the system was built around
# and the one that quietly stopped holding.
MAX_FILE_FRACTION_OF_HEAP = 1 / 3


def read_percent(text: str, pattern: str, label: str) -> int:
    m = re.search(pattern, text)
    if not m:
        print(f"Could not find {label} in {ENTRYPOINT} — this check needs updating.", file=sys.stderr)
        raise SystemExit(1)
    return int(m.group(1))


def main() -> int:
    if not ENTRYPOINT.exists():
        print(f"{ENTRYPOINT} not found; run from the repository root.", file=sys.stderr)
        return 1

    text = ENTRYPOINT.read_text()
    heap_pct = read_percent(text, r"JVM_HEAP_PERCENT=\$\{JVM_HEAP_PERCENT:-(\d+)\}", "JVM_HEAP_PERCENT")
    upload_pct = read_percent(text, r"MAX_UPLOAD_BYTES=\$\(\(\s*EFFECTIVE_MEM_MB \* (\d+) / 100", "the upload percentage")

    failures = []

    allowed = heap_pct * MAX_FILE_FRACTION_OF_HEAP
    if upload_pct > allowed:
        failures.append(
            f"Upload cap is {upload_pct}% of the memory budget, but the heap is only {heap_pct}%.\n"
            f"    A capture may be at most 1/{int(1/MAX_FILE_FRACTION_OF_HEAP)} of the heap, so the cap\n"
            f"    must not exceed {allowed:.1f}%. At APP_MEMORY_MB=2048 that is "
            f"{int(2048 * allowed / 100)}MB, not {int(2048 * upload_pct / 100)}MB.\n"
            f"    Lower the upload percentage, or raise the heap percentage and re-check that\n"
            f"    native subprocesses still fit (see the entrypoint's budget comment)."
        )

    # The limit is only real if the code that rejects uploads actually consults it.
    if FILE_SERVICE.exists():
        service = FILE_SERVICE.read_text()
        if re.search(r"MAX_FILE_SIZE\s*=\s*\d+\s*\*", service):
            failures.append(
                f"{FILE_SERVICE} hardcodes a maximum file size.\n"
                f"    It must read app.max-file-size, or the number shown to the user by\n"
                f"    /system/limits and the number actually enforced will drift apart again."
            )

    if failures:
        print("Memory budget is inconsistent:\n")
        for f in failures:
            print(f"  - {f}\n")
        return 1

    budget = 2048
    print(
        f"Memory budget OK — heap {heap_pct}%, upload cap {upload_pct}% "
        f"({int(budget * upload_pct / 100)}MB of a {int(budget * heap_pct / 100)}MB heap "
        f"at APP_MEMORY_MB={budget})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
