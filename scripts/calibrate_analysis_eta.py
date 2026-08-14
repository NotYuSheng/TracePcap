#!/usr/bin/env python3
"""Derive the analysis-ETA coefficients in FileMapper from real runs.

The constants in `FileMapper` are seconds-per-1000-packets per stage, and they are only as good
as the runs they were fitted to. They were fitted once, against a 21.4k-packet capture, before the
warm Suricata engine (#569) removed the cost they were mostly describing — after which they said
Suricata was the dominant term while it had become the cheapest.

This reads the per-stage timings the pipeline already logs and prints measured coefficients, so a
recalibration is a command rather than an afternoon with a calculator.

Usage:
    docker compose logs backend | python3 scripts/calibrate_analysis_eta.py

Feed it logs covering at least two captures of very different sizes: a single point cannot tell a
per-packet cost from a fixed one, which is exactly how the current constants went wrong.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict

STAGE = re.compile(r"\[([0-9a-f-]{36})\] \[(\d)/7\] ([A-Za-z +&-]+?): (\d+)ms")
PARSE = re.compile(r"\[([0-9a-f-]{36})\] \[2/7\] PCAP parse: \d+ms\s+\((\d+) packets")
DONE = re.compile(r"\[([0-9a-f-]{36})\] Analysis complete: total (\d+)ms")

# Which stages make up each coefficient in FileMapper.
BASE = {2, 4, 5, 6}      # parse + classify/geo + save + DB insert
EXTRACT = {3}            # nDPI + Suricata
FILE_EXTRACTION = {7}


def main() -> int:
    stages: dict[str, dict[int, int]] = defaultdict(dict)
    packets: dict[str, int] = {}
    totals: dict[str, int] = {}

    for line in sys.stdin:
        if (m := PARSE.search(line)):
            packets[m.group(1)] = int(m.group(2))
        if (m := STAGE.search(line)):
            stages[m.group(1)][int(m.group(2))] = int(m.group(4))
        if (m := DONE.search(line)):
            totals[m.group(1)] = int(m.group(2))

    runs = [(f, packets[f], stages[f], totals[f])
            for f in totals if f in packets and packets[f] > 0]
    if not runs:
        print("No complete runs found in the input.", file=sys.stderr)
        return 1

    runs.sort(key=lambda r: r[1])
    print(f"{'packets':>10} {'total s':>9} {'base':>8} {'extract':>9} {'file-ext':>9}   (s per 1000 packets)")
    agg = defaultdict(list)
    for _, pkts, st, total in runs:
        k = pkts / 1000.0
        row = {
            "base": sum(st.get(i, 0) for i in BASE) / 1000 / k,
            "extract": sum(st.get(i, 0) for i in EXTRACT) / 1000 / k,
            "file-ext": sum(st.get(i, 0) for i in FILE_EXTRACTION) / 1000 / k,
        }
        for key, val in row.items():
            agg[key].append((pkts, val))
        print(f"{pkts:>10} {total/1000:>9.1f} {row['base']:>8.3f} {row['extract']:>9.3f} {row['file-ext']:>9.3f}")

    print("\nPer-packet cost is only real if it holds across sizes. Compare the smallest and")
    print("largest run below: a coefficient that shrinks as captures grow was a fixed cost")
    print("wearing a per-packet costume.\n")
    for key, points in agg.items():
        if len(points) < 2:
            print(f"  {key:>9}: one run only — cannot separate fixed from per-packet")
            continue
        (small_n, small_v), (large_n, large_v) = points[0], points[-1]
        drift = (large_v / small_v) if small_v else float("inf")
        verdict = "looks per-packet" if 0.5 <= drift <= 2 else "NOT per-packet — fixed cost leaking in"
        print(f"  {key:>9}: {small_v:.3f} @ {small_n} -> {large_v:.3f} @ {large_n}  ({verdict})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
