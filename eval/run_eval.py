#!/usr/bin/env python3
"""Evaluation harness for the autonomous-investigation epic (#819, Workstream A).

Scores TracePcap's *deterministic* conclusions (GET /answers + /knowledge) for each case against a
published answer key (cases/<id>/expected.yaml). This is the baseline number, measured BEFORE any
agent, so every later change to the technique library / orchestrator is measurable against it.

Scoring, per field:
  correct  every value the key lists was produced, and nothing else
  missed   no answer was produced (or only some of the key's values were)
  wrong    an answer was produced that the key does not list -- even if the right value is ALSO
           present. A spurious extra victim / C2 is a false accusation, so it counts here.

The headline metric is CONFIDENTLY WRONG (the count of `wrong` fields): the trust-killing failure
(the old Story mode's problem). It must stay at zero.

Exit codes: 0 all cases scored, nothing wrong; 1 something confidently wrong; 2 the run was
incomplete (a case was skipped or errored) -- in which case the scorecard is NOT rewritten, so a
partial run cannot clobber the committed baseline (use --allow-incomplete to override).

Dev/CI-time tool only -- it talks to a running stack over HTTP; it is not part of the offline
runtime. Requires PyYAML (`pip install -r eval/requirements.txt`).

Usage:
    python3 eval/run_eval.py [--api-base http://localhost/api/v1] [--upload-missing]
                             [--out-dir DIR] [--allow-incomplete]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = Path(__file__).resolve().parent
CASES_DIR = EVAL_DIR / "cases"
# Where a locally-fetched pcap may live (gitignored eval/pcaps/, or the demo copy in the build tree).
PCAP_SEARCH_DIRS = [EVAL_DIR / "pcaps", REPO_ROOT / "backend" / "target" / "ctf-demo"]

CORRECT, MISSED, WRONG, NA = "correct", "missed", "wrong", "n/a"


class ApiError(Exception):
    """A failure talking to the stack, with a message that says what actually went wrong."""


# --------------------------------------------------------------------------- HTTP helpers
def http_get_json(url: str, timeout: int = 60):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:  # before URLError: HTTPError is a subclass of it
        raise ApiError(f"HTTP {e.code} from {url}") from e
    except urllib.error.URLError as e:
        raise ApiError(f"cannot reach {url} ({e.reason}) -- is the stack up?") from e
    except (TimeoutError, json.JSONDecodeError) as e:
        raise ApiError(f"bad or slow response from {url}: {e}") from e


def find_file(api_base: str, pcap_name: str):
    """Newest completed file with this name -> (metadata, None); else (None, in-progress status|None).

    Walks every page (the list is newest-first and capped at 100 per page), so a busy server does
    not hide the target file on page 2+.
    """
    in_progress = None
    page = 1
    while True:
        data = http_get_json(f"{api_base}/files?page={page}&pageSize=100")
        for f in data.get("data", []):
            if f.get("fileName") != pcap_name:
                continue
            status = str(f.get("status", "")).lower()
            if status == "completed":
                return f, None
            in_progress = status or "unknown"
        if page >= int(data.get("totalPages") or page):
            return None, in_progress
        page += 1


def local_pcap(pcap_name: str):
    for d in PCAP_SEARCH_DIRS:
        p = d / pcap_name
        if p.is_file():
            return p
    return None


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def upload_and_wait(api_base: str, pcap_path: Path, expected_sha256: str | None, timeout: int = 900):
    """Upload a pcap and poll until analysis completes; return the file's metadata.

    Verifies the local capture's sha256 against the case manifest first -- scoring the wrong capture
    against a key would be a silent, meaningless result.
    """
    if expected_sha256:
        actual = sha256_of(pcap_path)
        if actual.lower() != expected_sha256.lower():
            raise ApiError(f"{pcap_path.name}: sha256 {actual} does not match the manifest "
                           f"({expected_sha256}) -- refusing to score a different capture")
    with tempfile.NamedTemporaryFile(suffix=".json") as body:
        out = subprocess.run(
            ["curl", "-sS", "-o", body.name, "-w", "%{http_code}", "-X", "POST",
             f"{api_base}/files", "-F", f"file=@{pcap_path}"],
            capture_output=True, text=True, timeout=300,
        )
        if out.returncode != 0:
            raise ApiError(f"upload failed: {out.stderr.strip() or 'curl exit ' + str(out.returncode)}")
        status = out.stdout.strip()
        try:
            payload = json.loads(Path(body.name).read_text() or "{}")
        except json.JSONDecodeError:
            payload = {}
    if status == "409":  # same content already uploaded: use it rather than fail
        file_id = payload.get("existingFileId")
    elif status == "201":
        file_id = payload.get("fileId") or payload.get("id")
    else:
        raise ApiError(f"upload returned HTTP {status}: {str(payload)[:200]}")
    if not file_id:
        raise ApiError(f"upload response carried no file id: {str(payload)[:200]}")

    deadline = time.time() + timeout
    while time.time() < deadline:
        meta = http_get_json(f"{api_base}/files/{file_id}")
        state = str(meta.get("status", "")).lower()
        if state == "completed":
            return meta
        if state in ("failed", "error"):
            raise ApiError(f"analysis failed for {pcap_path.name}")
        time.sleep(5)
    raise ApiError(f"analysis did not complete within {timeout}s for {pcap_path.name}")


# --------------------------------------------------------------------------- normalisation
def norm_text(v):
    return str(v).strip().lower() if v is not None else None


def norm_mac(v):
    """00:1E:64-ec.f3.08 / 001e64ecf308 -> 001e64ecf308: separator style is not a difference."""
    if v is None:
        return None
    digits = re.sub(r"[^0-9a-fA-F]", "", str(v)).lower()
    return digits or None


def norm_host(v):
    """DESKTOP-SKBR25F.local -> desktop-skbr25f: compare the machine label, not the DNS suffix."""
    return norm_text(str(v).split(".")[0]) if v else None


# --------------------------------------------------------------------------- scoring
def classify(expected, candidates, normalizer=norm_text):
    """Score one field. `expected` is a value or a list of values (a key may list several C2s).

    Extras count against the answer: producing a value the key does not list is `wrong` even when
    the right value is present too -- otherwise a regression that adds spurious victims / C2s would
    still score "correct" and the confidently-wrong gate would never fire.
    """
    exp = [e for e in (expected if isinstance(expected, list) else [expected]) if e is not None]
    if not exp:
        return NA, None
    exp_norm = {normalizer(e) for e in exp}

    produced = {}  # normalised -> first raw value, so the detail shows what was actually produced
    for c in candidates:
        if c is not None and normalizer(c) is not None:
            produced.setdefault(normalizer(c), c)

    spurious = [raw for n, raw in produced.items() if n not in exp_norm]
    missing = [e for e in exp if normalizer(e) not in produced]

    if spurious:
        return WRONG, {"spurious": spurious, "missing": missing}
    if not produced:
        return MISSED, None
    if missing:
        return MISSED, {"missing": missing}
    return CORRECT, exp[0] if len(exp) == 1 else exp


def answers_by_question(answers):
    out = {}
    for a in answers:
        out.setdefault(a.get("question"), []).append(a)
    return out


def entity(knowledge, etype, key):
    for e in knowledge.get("entities", []):
        if e.get("type") == etype and norm_text(e.get("key")) == norm_text(key):
            return e
    return None


def score_case(expected, answers, knowledge):
    """Return a list of per-field results for one case."""
    by_q = answers_by_question(answers)
    v = expected.get("victim", {}) or {}
    u = expected.get("user", {}) or {}
    m = expected.get("malware", {}) or {}
    c2_ips = [c.get("ip") for c in (expected.get("c2", []) or []) if c.get("ip")]
    victim_ip = v.get("ip")

    victim_hosts = [a.get("attributes", {}).get("host") for a in by_q.get("victim", [])]
    # The account is scored against the VICTIM's sign-in, not any host's: another machine having
    # "ccollier" signed in must not make a wrong attribution to the victim look correct.
    signed_in = by_q.get("signed-in-user", [])
    if victim_ip:
        signed_in = [a for a in signed_in if norm_text(a.get("attributes", {}).get("host")) == norm_text(victim_ip)]
    user_accts = [a.get("attributes", {}).get("user") for a in signed_in]
    malwares = [a.get("attributes", {}).get("family") for a in by_q.get("malware", [])]
    c2_addrs = [a.get("attributes", {}).get("address") for a in by_q.get("c2", [])]

    host_attrs = (entity(knowledge, "HOST", victim_ip) or {}).get("attributes", {}) if victim_ip else {}
    user_attrs = (entity(knowledge, "USER", u.get("account")) or {}).get("attributes", {}) if u.get("account") else {}
    # a real name would live under one of these keys if we ever surface it (LDAP person-DN)
    real_name_cands = [user_attrs.get(k) for k in ("realName", "real_name", "displayName", "cn")]

    fields = [
        ("victim.ip", *classify(victim_ip, victim_hosts)),
        ("victim.mac", *classify(v.get("mac"), [host_attrs.get("mac")], norm_mac)),
        ("victim.hostname", *classify(v.get("hostname"), [host_attrs.get("hostname")], norm_host)),
        ("user.account", *classify(u.get("account"), user_accts)),
        ("user.real_name", *classify(u.get("real_name"), real_name_cands)),
        ("malware.family", *classify(m.get("family"), malwares)),
        ("c2.ip", *classify(c2_ips or None, c2_addrs)),
    ]
    return [{"field": f, "status": s, "detail": d} for (f, s, d) in fields]


# --------------------------------------------------------------------------- runner
def load_case(case_dir: Path):
    expected = yaml.safe_load((case_dir / "expected.yaml").read_text())
    case = {}
    if (case_dir / "case.yaml").is_file():
        case = yaml.safe_load((case_dir / "case.yaml").read_text()) or {}
    return expected, case


def run_case(case_dir: Path, api_base: str, upload_missing: bool):
    expected, case = load_case(case_dir)
    case_id = expected.get("case_id", case_dir.name)
    pcap_name = case.get("pcap")

    meta, in_progress = (find_file(api_base, pcap_name) if pcap_name else (None, None))
    if not meta and upload_missing and pcap_name and not in_progress:
        p = local_pcap(pcap_name)
        if p:
            print(f"[{case_id}] uploading {p} ...", file=sys.stderr)
            meta = upload_and_wait(api_base, p, case.get("sha256"))

    if not meta:
        why = (f"'{pcap_name}' is still {in_progress} on the server -- wait for it to finish"
               if in_progress else
               f"no analyzed file '{pcap_name}' on the server (place the pcap under eval/pcaps/ and "
               f"use --upload-missing; see case.yaml for where to get it)")
        return {"case_id": case_id, "status": "pcap_unavailable", "reason": why, "fields": []}

    file_id = meta["fileId"]
    answers = http_get_json(f"{api_base}/files/{file_id}/answers")
    knowledge = http_get_json(f"{api_base}/files/{file_id}/knowledge")
    return {
        "case_id": case_id,
        "status": "scored",
        # what the analysis had switched on -- a Suricata-off run is a different (harder) test than a
        # Suricata-on one, so the scorecard must say which it measured. No file id: it changes on
        # every re-upload and would make the committed scorecard diff on every run.
        "analysis": {
            "suricata": meta.get("enableSuricata"),
            "ndpi": meta.get("enableNdpi"),
            "fileExtraction": meta.get("enableFileExtraction"),
        },
        "fields": score_case(expected, answers, knowledge),
    }


def run(api_base: str, upload_missing: bool):
    results = []
    for case_dir in sorted(p for p in CASES_DIR.iterdir() if p.is_dir()):
        if not (case_dir / "expected.yaml").is_file():
            continue
        try:
            results.append(run_case(case_dir, api_base, upload_missing))
        except ApiError as e:  # one case failing must not abort the rest or lose their results
            print(f"[{case_dir.name}] ERROR -- {e}", file=sys.stderr)
            results.append({"case_id": case_dir.name, "status": "error", "reason": str(e), "fields": []})
    return results


def summarize(results):
    tally = {CORRECT: 0, MISSED: 0, WRONG: 0, NA: 0}
    for r in results:
        for f in r.get("fields", []):
            tally[f["status"]] = tally.get(f["status"], 0) + 1
    scored = tally[CORRECT] + tally[MISSED] + tally[WRONG]
    return {
        "cases": len(results),
        "cases_scored": sum(1 for r in results if r.get("status") == "scored"),
        "scored_fields": scored,
        "correct": tally[CORRECT],
        "missed": tally[MISSED],
        "confidently_wrong": tally[WRONG],
        "accuracy": round(tally[CORRECT] / scored, 3) if scored else None,
    }


def is_incomplete(results):
    return not results or any(r.get("status") != "scored" for r in results)


def fmt_detail(d):
    if d is None:
        return ""
    if isinstance(d, dict):
        parts = []
        if d.get("spurious"):
            parts.append("spurious: " + ", ".join(map(str, d["spurious"])))
        if d.get("missing"):
            parts.append("missing: " + ", ".join(map(str, d["missing"])))
        return "; ".join(parts)
    return ", ".join(map(str, d)) if isinstance(d, list) else str(d)


def write_scorecard(results, summary, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scorecard.json").write_text(
        json.dumps({"summary": summary, "cases": results}, indent=2) + "\n")

    lines = ["# Evaluation scorecard", "",
             "Baseline of TracePcap's **deterministic** conclusions vs. published answer keys "
             "(#819, Workstream A). Regenerate with `python3 eval/run_eval.py`.", "",
             f"- Cases scored: **{summary['cases_scored']}** of {summary['cases']}",
             f"- Correct: **{summary['correct']}** / {summary['scored_fields']} "
             f"(accuracy {summary['accuracy']})",
             f"- Missed: **{summary['missed']}**",
             f"- Confidently wrong: **{summary['confidently_wrong']}** "
             f"{'✅' if summary['confidently_wrong'] == 0 else '❌'}", ""]
    icon = {CORRECT: "✅", MISSED: "◻️", WRONG: "❌", NA: "—"}
    for r in results:
        lines.append(f"## {r['case_id']}")
        if r["status"] != "scored":
            lines.append(f"_{r['status']}: {r.get('reason', '')}_\n")
            continue
        a = r.get("analysis") or {}
        lines.append(f"Analysis: Suricata **{'on' if a.get('suricata') else 'off'}**, "
                     f"nDPI {'on' if a.get('ndpi') else 'off'}.\n")
        lines.append("| Field | Status | Detail |")
        lines.append("|---|---|---|")
        for f in r["fields"]:
            lines.append(f"| {f['field']} | {icon.get(f['status'], f['status'])} {f['status']} | {fmt_detail(f['detail'])} |")
        lines.append("")
    (out_dir / "scorecard.md").write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-base", default=os.environ.get("TRACEPCAP_API", "http://localhost/api/v1"))
    ap.add_argument("--upload-missing", action="store_true",
                    help="upload a local pcap (sha256-checked) when no analyzed file of that name exists")
    ap.add_argument("--out-dir", type=Path, default=EVAL_DIR,
                    help="where to write scorecard.md/json (default: eval/, the committed baseline)")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="write the scorecard even if a case was skipped or errored")
    args = ap.parse_args()

    try:
        results = run(args.api_base, args.upload_missing)
    except ApiError as e:
        print(f"ERROR -- {e}", file=sys.stderr)
        return 2
    summary = summarize(results)
    incomplete = is_incomplete(results)

    if incomplete and not args.allow_incomplete:
        print("INCOMPLETE run -- scorecard NOT written (it would overwrite the baseline with a partial "
              "result). Use --allow-incomplete to force.", file=sys.stderr)
    else:
        write_scorecard(results, summary, args.out_dir)

    print(json.dumps(summary, indent=2))
    if summary["confidently_wrong"]:
        return 1
    return 2 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
