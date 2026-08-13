#!/usr/bin/env python3
"""Fail if any compose file makes the capture bucket anonymously readable.

Raw PCAPs are the most sensitive artefact the system holds: they carry credentials from
cleartext protocols, session tokens and internal topology. `mc anonymous set public` put them
behind no authentication at all (#637), and object names being UUIDs is obscurity rather than
access control — the bucket was listable, so the UUIDs were enumerable in one request.

Static, so it runs in CI without standing up a stack. It checks the declaration rather than a
live bucket; the live policy is asserted once by the system test.
"""
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
COMPOSE = sorted(REPO.glob("docker-compose*.yml"))

# Any mc subcommand that can grant anonymous access, not just the one this repo used. `policy
# set` is the older spelling and `anonymous set-json` takes a policy document — a guard that only
# knew `anonymous set` would wave both through, which is the failure mode it exists to prevent.
ANON = re.compile(r"mc\s+(?:anonymous|policy)\s+set(?:-json)?\s+(\S+)")
ANON_SAFE = {"none"}

# Any published mapping whose *target* is 9000, in either short or long syntax. Matching the
# literal "9000:9000" would miss "127.0.0.1:9000:9000", "9000:9000/tcp" and the long form.
PORT_SHORT = re.compile(r'^\s*-\s*["\']?(?:[\d.]+:)?(\d+):9000(?:/\w+)?["\']?\s*$')
PORT_LONG_TARGET = re.compile(r'^\s*target:\s*9000\s*$')

failures = []

for path in COMPOSE:
    text = path.read_text()
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        m = ANON.search(line)
        if m and m.group(1) not in ANON_SAFE:
            failures.append(
                f"{path.name}:{lineno} grants anonymous '{m.group(1)}' on the capture bucket."
                f"\n    Use `mc anonymous set none` — it also revokes a policy set by an earlier"
                f"\n    deploy, which simply deleting the line would not."
            )
        if PORT_SHORT.match(line) or PORT_LONG_TARGET.match(line):
            failures.append(
                f"{path.name}:{lineno} publishes the MinIO S3 API on the host."
                f"\n    The backend reaches MinIO over the compose network; a host mapping only"
                f"\n    widens who can reach object storage. Publish 9001 (console) instead."
            )

if failures:
    print("FAIL — object storage would be reachable without credentials:\n")
    for f in failures:
        print(f"  {f}\n")
    print("See #637. Captures must not be downloadable without authenticating.")
    sys.exit(1)

print(f"OK — {len(COMPOSE)} compose file(s): bucket is private, S3 API not published.")
