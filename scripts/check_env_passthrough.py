#!/usr/bin/env python3
"""Fail if backend environment variables and Spring config disagree, either way.

The failure this catches is silent: the variable is documented, an operator sets
it in .env, nothing happens, and the deployment quietly runs on the default. It
has shipped twice — the retention settings (#628) and eleven more including
CORS_ALLOWED_ORIGINS and GEO_ENRICHMENT_ENABLED (#641).

It checks both directions, because each has already bitten:

  * **Read but not passed** — the variable is documented, an operator sets it in
    .env, nothing happens, and the deployment runs on the default (#628, #641).
  * **Passed but not read** — compose supplies a knob no Spring config consumes,
    so it looks configurable and does nothing. GEO_TIMEOUT_SECONDS shipped this
    way and was removed in #653; the check that was supposed to prevent that
    class only looked in one direction.

Two things it is deliberately careful about:

  * It reads every Spring profile a stack activates, not just application.yml —
    CORS_ALLOWED_ORIGINS is declared in application-prod.yml, and a check that
    ignored profile files would miss that whole class.
  * It parses YAML and looks only at services.backend.environment. Grepping the
    compose file whole would let a variable in the postgres service, or merely
    mentioned in a comment, satisfy the backend's requirement.

Usage: python3 scripts/check_env_passthrough.py
Exit:  0 clean, 1 unreachable variables found
"""

import pathlib
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER = re.compile(r"\$\{([A-Z][A-Z0-9_]*)[:}]")

# Backend variables consumed outside Spring, so absent from the config files by
# design. Kept as an explicit list rather than prefix matching — a broad pattern
# like "LLM_*" would hide a genuinely dead knob in the same family, which is the
# failure this half of the check exists to catch.
PASSTHROUGH = {
    "APP_MEMORY_MB": "read by backend/docker-entrypoint.sh to size the heap and upload limit",
    "TZ":            "container timezone, consumed by the OS not the application",
}

# Each deployable stack: the compose files layered in order, and the Spring
# profile files active for it. Checked independently — a variable passed only by
# the offline file is still unreachable from the base stack.
STACKS = {
    "dev":          (["docker-compose.yml"], ["application.yml"]),
    "prod":         (["docker-compose.yml", "docker-compose.prod.yml"],
                     ["application.yml", "application-prod.yml"]),
    "offline":      (["docker-compose.offline.yml"], ["application.yml"]),
    "offline-prod": (["docker-compose.offline.yml", "docker-compose.offline-prod.yml"],
                     ["application.yml", "application-prod.yml"]),
}

# Supplied by other legitimate means. Each needs a reason — if you are adding
# here, be sure it is genuinely supplied, not merely unimportant.
EXEMPT = {
    "MAX_UPLOAD_SIZE_BYTES":   "passed as -D by backend/docker-entrypoint.sh, derived from the memory budget",
    "ANALYSIS_TIMEOUT_SECONDS": "passed as -D by backend/docker-entrypoint.sh, derived from the memory budget",
    "JACKSON_MAX_STRING_LENGTH": "passed as -D by backend/docker-entrypoint.sh, derived from the memory budget",
    "SERVER_PORT":             "internal; fixed at 8080 behind nginx",
    "SPRING_PROFILES_ACTIVE":  "set per compose file to select the profile",
    "LOG_DIR":                 "set by backend/docker-entrypoint.sh",
    # Deliberately passed by the production overlays only. Setting it in the base
    # file would either leak the dev profile's localhost origins into production,
    # or — passed empty — defeat the dev default, since Spring treats an empty env
    # var as set. See docker-compose.prod.yml.
    "CORS_ALLOWED_ORIGINS":    "prod overlays only, by design",
    # Derived from PUBLIC_URL by the auth overlays; meaningless with auth off.
    "KEYCLOAK_ISSUER_URI":     "set by the auth overlays from PUBLIC_URL",
    "KEYCLOAK_JWK_SET_URI":    "set by the auth overlays (internal service address)",
}


def vars_read(profile_files):
    """Placeholders referenced by the Spring config files a stack activates."""
    found = set()
    for name in profile_files:
        path = ROOT / "backend/src/main/resources" / name
        if path.exists():
            found |= set(PLACEHOLDER.findall(path.read_text()))
    return found


def vars_passed(compose_files):
    """Keys under services.backend.environment, merged in overlay order."""
    passed = set()
    for name in compose_files:
        doc = yaml.safe_load((ROOT / name).read_text()) or {}
        env = (doc.get("services", {}).get("backend", {}) or {}).get("environment")
        if isinstance(env, dict):
            passed |= {k for k in env if k}
        elif isinstance(env, list):          # "KEY=value" form
            passed |= {item.split("=", 1)[0] for item in env}
    return passed


# Internal wiring rather than operator knobs: compose builds these from variables .env.example
# does document (DATABASE_URL from POSTGRES_DB, MINIO_ACCESS_KEY from MINIO_ROOT_USER, and so on).
# Documenting the derived name would invite someone to set it and wonder why the source still won.
INTERNAL_WIRING = {
    "DATABASE_URL",
    "DATABASE_USERNAME",
    "DATABASE_PASSWORD",
    "MINIO_ENDPOINT",
    "MINIO_ACCESS_KEY",
    "MINIO_SECRET_KEY",
    "MINIO_BUCKET",
    "TZ",
}


def documented_vars(path="\u002eenv.example"):
    """Variables .env.example mentions, commented-out ones included.

    A commented default still documents that the knob exists, which is the point — an operator
    reads this file to learn what is tunable.
    """
    example = pathlib.Path(path)
    if not example.is_absolute():
        example = ROOT / example
    text = example.read_text() if example.exists() else ""
    return set(re.findall(r"^#?\s*([A-Z_][A-Z0-9_]*)=", text, re.M))


def main():
    unreachable, dead, undocumented = [], [], []
    for stack, (compose_files, profile_files) in sorted(STACKS.items()):
        reachable = vars_passed(compose_files)
        read = vars_read(profile_files)
        # Declared by Spring, never supplied by compose: setting it does nothing.
        unreachable.extend(
            (stack, var)
            for var in sorted(read)
            if var not in EXEMPT and var not in reachable
        )
        # Supplied by compose, read by no Spring config: a knob that does nothing.
        # PASSTHROUGH covers the few consumed outside Spring entirely.
        dead.extend(
            (stack, var)
            for var in sorted(reachable)
            if var not in EXEMPT and var not in read and var not in PASSTHROUGH
        )

    # Third edge of the same triangle: compose <-> application.yml was already checked, but a
    # variable can be wired end to end and still be invisible, because nothing tells the operator
    # it exists. .env.example is the only place they look.
    documented = documented_vars()
    passed_by_any_stack = set()
    for compose_files, _ in STACKS.values():
        passed_by_any_stack |= vars_passed(compose_files)
    undocumented.extend(
        var
        for var in sorted(passed_by_any_stack)
        if var not in EXEMPT and var not in INTERNAL_WIRING and var not in documented
    )

    if undocumented:
        print("Passed to the backend but absent from .env.example:\n")
        for var in undocumented:
            print(f"  {var}")
        print("\nAdd each with a short note on what it does and its default. A setting nobody")
        print("knows about is not configurable.\n")

    if not unreachable and not dead and not undocumented:
        print("OK — compose, Spring config and .env.example all agree.")
        return 0

    if unreachable:
        print("FAIL — the backend reads these, but the stack's compose files never pass")
        print("them to services.backend.environment. Setting them has no effect.\n")
        for stack, var in unreachable:
            print(f"  {stack:14} {var}")
        print("\nFix: add each to the backend environment of that stack's compose file,")
        print("using ${VAR:-default} with the default from application.yml.\n")

    if dead:
        print("FAIL — compose passes these to the backend, but no Spring config file")
        print("reads them. They look configurable and do nothing.\n")
        for stack, var in dead:
            print(f"  {stack:14} {var}")
        print("\nFix: remove them from the compose file, or add the property to")
        print("application.yml if the setting was meant to work.\n")

    print("If a variable is supplied or consumed another way, add it to EXEMPT")
    print("or PASSTHROUGH here with the reason.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
