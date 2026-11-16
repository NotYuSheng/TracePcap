#!/usr/bin/env bash
# Refuse to start a heavy job (image builds, a recording, the full test suites) when the machine is
# already short of memory. On a 15 GB machine running VS Code, its Java language servers and the
# stack, a heavy job on top of a filled swap thrashes the disk until the machine freezes (it did,
# 2026-11-16: swap 59% used, then a recording started an analysis and a video-recording browser).
#
# usage: scripts/mem-guard.sh "<what is about to run>" [min-available-GB]
# Env: MEM_GUARD_MIN_GB (default 4), MEM_GUARD_MAX_SWAP_PCT (default 40), MEM_GUARD=off to skip.
set -euo pipefail

what="${1:-a heavy job}"
min_gb="${2:-${MEM_GUARD_MIN_GB:-4}}"
max_swap="${MEM_GUARD_MAX_SWAP_PCT:-40}"

[ "${MEM_GUARD:-on}" = "off" ] && exit 0
[ -r /proc/meminfo ] || exit 0   # not Linux: nothing to check

kb() { awk -v k="$1" '$1==k":" {print $2}' /proc/meminfo; }
avail_kb="$(kb MemAvailable)"
swap_total_kb="$(kb SwapTotal)"
swap_free_kb="$(kb SwapFree)"
avail_gb=$(awk -v a="$avail_kb" 'BEGIN {printf "%.1f", a/1048576}')
swap_pct=0
if [ "${swap_total_kb:-0}" -gt 0 ]; then
  swap_pct=$(( (swap_total_kb - swap_free_kb) * 100 / swap_total_kb ))
fi

problems=()
if awk -v a="$avail_gb" -v m="$min_gb" 'BEGIN {exit !(a < m)}'; then
  problems+=("only ${avail_gb} GB of memory is available (need ${min_gb} GB)")
fi
if [ "$swap_pct" -gt "$max_swap" ]; then
  problems+=("swap is ${swap_pct}% used (limit ${max_swap}%): the machine is already paging")
fi

if [ "${#problems[@]}" -gt 0 ]; then
  echo "mem-guard: not starting ${what}:" >&2
  for p in "${problems[@]}"; do echo "  - $p" >&2; done
  echo "  Free memory first (close what you don't need; stop the stack if this job doesn't need it)," >&2
  echo "  or run it anyway with MEM_GUARD=off." >&2
  echo "  Biggest users now:" >&2
  ps -eo rss,comm --sort=-rss | awk 'NR>1 && NR<=7 {printf "    %6.0f MB  %s\n", $1/1024, $2}' >&2
  exit 1
fi
echo "mem-guard: ${avail_gb} GB available, swap ${swap_pct}% used: ok to start ${what}."
