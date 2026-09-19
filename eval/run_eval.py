#!/usr/bin/env python3
"""Evaluation harness for the autonomous-investigation epic (#819, Workstream A).

Scores TracePcap's *deterministic* conclusions (GET /answers + /knowledge) for each case against a
published answer key (cases/<id>/expected.yaml). This is the baseline number, measured BEFORE any
agent, so every later change to the technique library / orchestrator is measurable against it.

The headline metric is CONFIDENTLY WRONG: a field where TracePcap produced an answer that contradicts
the key. That is the trust-killing failure (the old Story mode's problem), and it must stay at zero.

Dev/CI-time tool only — it talks to a running stack over HTTP; it is not part of the offline runtime.

Usage:
    python3 eval/run_eval.py [--api-base http://localhost/api/v1] [--upload-missing]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
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


# --------------------------------------------------------------------------- HTTP helpers
def http_get_json(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def find_analyzed_file(api_base: str, pcap_name: str):
    """Return the fileId of an already-analyzed file with this name, or None."""
    try:
        data = http_get_json(f"{api_base}/files?page=1&pageSize=100")
    except urllib.error.URLError as e:
        raise SystemExit(f"Cannot reach the API at {api_base} ({e}). Is the stack up?")
    for f in data.get("data", []):
        if f.get("fileName") == pcap_name and str(f.get("status", "")).lower() == "completed":
            return f.get("fileId")
    return None


def local_pcap(pcap_name: str):
    for d in PCAP_SEARCH_DIRS:
        p = d / pcap_name
        if p.is_file():
            return p
    return None


def upload_and_wait(api_base: str, pcap_path: Path, timeout: int = 900):
    """Upload a pcap via multipart and poll until analysis completes; return the fileId."""
    out = subprocess.run(
        ["curl", "-s", "-X", "POST", f"{api_base}/files", "-F", f"file=@{pcap_path}"],
        capture_output=True, text=True, timeout=120,
    )
    resp = json.loads(out.stdout)
    file_id = resp.get("fileId") or resp.get("id")
    if not file_id:
        raise RuntimeError(f"Upload did not return a fileId: {out.stdout[:200]}")
    deadline = time.time() + timeout
    while time.time() < deadline:
        meta = http_get_json(f"{api_base}/files/{file_id}")
        if str(meta.get("status", "")).lower() == "completed":
            return file_id
        if str(meta.get("status", "")).lower() in ("failed", "error"):
            raise RuntimeError(f"Analysis failed for {pcap_path.name}")
        time.sleep(5)
    raise TimeoutError(f"Analysis did not complete within {timeout}s for {pcap_path.name}")


# --------------------------------------------------------------------------- scoring
def norm(v):
    return str(v).strip().lower() if v is not None else None


def host_short(name):
    """DESKTOP-SKBR25F.local -> desktop-skbr25f, for hostname comparison across sources."""
    return norm(name.split(".")[0]) if name else None


def answers_by_question(answers):
    out = {}
    for a in answers:
        out.setdefault(a.get("question"), []).append(a)
    return out


def entity(knowledge, etype, key):
    for e in knowledge.get("entities", []):
        if e.get("type") == etype and norm(e.get("key")) == norm(key):
            return e
    return None


def classify(expected, candidates, normalizer=norm):
    """correct if expected is among the produced candidates; missed if none produced; else wrong."""
    if expected is None:
        return NA, None
    cand = [c for c in candidates if c is not None]
    if not cand:
        return MISSED, None
    exp_n = normalizer(expected)
    cand_n = [normalizer(c) for c in cand]
    if exp_n in cand_n:
        return CORRECT, expected
    return WRONG, cand  # produced something, but it contradicts the key


def score_case(expected, answers, knowledge):
    """Return a list of per-field results for one case."""
    by_q = answers_by_question(answers)
    v = expected.get("victim", {}) or {}
    u = expected.get("user", {}) or {}
    m = expected.get("malware", {}) or {}
    c2_list = expected.get("c2", []) or []
    c2_ip = c2_list[0].get("ip") if c2_list else None

    # candidates TracePcap produced, per field
    victim_ips = [a.get("attributes", {}).get("host") for a in by_q.get("victim", [])]
    user_accts = [a.get("attributes", {}).get("user") for a in by_q.get("signed-in-user", [])]
    malwares = [a.get("attributes", {}).get("family") for a in by_q.get("malware", [])]
    c2_addrs = [a.get("attributes", {}).get("address") for a in by_q.get("c2", [])]

    host_ent = entity(knowledge, "HOST", v.get("ip")) if v.get("ip") else None
    host_attrs = (host_ent or {}).get("attributes", {})
    user_ent = entity(knowledge, "USER", u.get("account")) if u.get("account") else None
    user_attrs = (user_ent or {}).get("attributes", {})
    # a real name would live under one of these keys if we ever surface it (LDAP person-DN)
    real_name_cands = [user_attrs.get(k) for k in ("realName", "real_name", "displayName", "cn")]

    fields = [
        ("victim.ip", *classify(v.get("ip"), victim_ips)),
        ("victim.mac", *classify(v.get("mac"), [host_attrs.get("mac")])),
        ("victim.hostname", *classify(v.get("hostname"), [host_attrs.get("hostname")], host_short)),
        ("user.account", *classify(u.get("account"), user_accts)),
        ("user.real_name", *classify(u.get("real_name"), real_name_cands)),
        ("malware.family", *classify(m.get("family"), malwares)),
        ("c2.ip", *classify(c2_ip, c2_addrs)),
    ]
    return [{"field": f, "status": s, "detail": d} for (f, s, d) in fields]


# --------------------------------------------------------------------------- runner
def load_case(case_dir: Path):
    expected = yaml.safe_load((case_dir / "expected.yaml").read_text())
    case = {}
    if (case_dir / "case.yaml").is_file():
        case = yaml.safe_load((case_dir / "case.yaml").read_text())
    return expected, case


def run(api_base: str, upload_missing: bool):
    results = []
    for case_dir in sorted(p for p in CASES_DIR.iterdir() if p.is_dir()):
        if not (case_dir / "expected.yaml").is_file():
            continue
        expected, case = load_case(case_dir)
        case_id = expected.get("case_id", case_dir.name)
        pcap_name = case.get("pcap")

        file_id = find_analyzed_file(api_base, pcap_name) if pcap_name else None
        if not file_id and upload_missing and pcap_name:
            p = local_pcap(pcap_name)
            if p:
                print(f"[{case_id}] uploading {p} …", file=sys.stderr)
                file_id = upload_and_wait(api_base, p)

        if not file_id:
            print(f"[{case_id}] SKIP — no analyzed file '{pcap_name}' on the server "
                  f"(run with --upload-missing and place the pcap locally)", file=sys.stderr)
            results.append({"case_id": case_id, "status": "pcap_unavailable", "fields": []})
            continue

        answers = http_get_json(f"{api_base}/files/{file_id}/answers")
        knowledge = http_get_json(f"{api_base}/files/{file_id}/knowledge")
        fields = score_case(expected, answers, knowledge)
        results.append({"case_id": case_id, "file_id": file_id, "status": "scored", "fields": fields})
    return results


def summarize(results):
    tally = {CORRECT: 0, MISSED: 0, WRONG: 0, NA: 0}
    for r in results:
        for f in r.get("fields", []):
            tally[f["status"]] = tally.get(f["status"], 0) + 1
    scored = tally[CORRECT] + tally[MISSED] + tally[WRONG]
    return {
        "cases": len(results),
        "scored_fields": scored,
        "correct": tally[CORRECT],
        "missed": tally[MISSED],
        "confidently_wrong": tally[WRONG],
        "accuracy": round(tally[CORRECT] / scored, 3) if scored else None,
    }


def write_scorecard(results, summary, out_dir: Path):
    (out_dir / "scorecard.json").write_text(
        json.dumps({"summary": summary, "cases": results}, indent=2) + "\n")

    lines = ["# Evaluation scorecard", "",
             "Baseline of TracePcap's **deterministic** conclusions vs. published answer keys "
             "(#819, Workstream A). Regenerate with `python3 eval/run_eval.py`.", "",
             f"- Cases: **{summary['cases']}**",
             f"- Correct: **{summary['correct']}** / {summary['scored_fields']} "
             f"(accuracy {summary['accuracy']})",
             f"- Missed: **{summary['missed']}**",
             f"- Confidently wrong: **{summary['confidently_wrong']}** "
             f"{'✅' if summary['confidently_wrong'] == 0 else '❌'}", ""]
    icon = {CORRECT: "✅", MISSED: "◻️", WRONG: "❌", NA: "—"}
    for r in results:
        lines.append(f"## {r['case_id']}")
        if r["status"] != "scored":
            lines.append(f"_{r['status']}_\n")
            continue
        lines.append("| Field | Status | Detail |")
        lines.append("|---|---|---|")
        for f in r["fields"]:
            d = f["detail"]
            d = ", ".join(map(str, d)) if isinstance(d, list) else (d if d is not None else "")
            lines.append(f"| {f['field']} | {icon.get(f['status'], f['status'])} {f['status']} | {d} |")
        lines.append("")
    (out_dir / "scorecard.md").write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-base", default=os.environ.get("TRACEPCAP_API", "http://localhost/api/v1"))
    ap.add_argument("--upload-missing", action="store_true",
                    help="upload a local pcap when no analyzed file of that name exists on the server")
    args = ap.parse_args()

    results = run(args.api_base, args.upload_missing)
    summary = summarize(results)
    write_scorecard(results, summary, EVAL_DIR)

    print(json.dumps(summary, indent=2))
    # Non-zero exit if anything is confidently wrong — the metric a CI job would gate on.
    sys.exit(1 if summary["confidently_wrong"] else 0)


if __name__ == "__main__":
    main()
