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

# `mc anonymous set <policy>` — anything other than `none` grants some anonymous access.
ANON = re.compile(r"mc\s+anonymous\s+set\s+(\w+)")
# Publishing the S3 API on the host widens who can reach object storage; the backend uses the
# compose network. The console (9001) is fine.
PORT_9000 = re.compile(r'^\s*-\s*"9000:9000"')

failures = []

for path in COMPOSE:
    text = path.read_text()
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        m = ANON.search(line)
        if m and m.group(1) != "none":
            failures.append(
                f"{path.name}:{lineno} grants anonymous '{m.group(1)}' on the capture bucket."
                f"\n    Use `mc anonymous set none` — it also revokes a policy set by an earlier"
                f"\n    deploy, which simply deleting the line would not."
            )
        if PORT_9000.match(line):
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
