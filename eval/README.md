# Investigation evaluation harness (#819, Workstream A)

Scores TracePcap's **deterministic** conclusions against published answer keys, so the autonomous
investigation work (#819) has a measurable baseline *before* any agent, and so regressions are caught.

The metric that matters is **confidently wrong** — a field where TracePcap produced an answer the key
does not list. That is the trust-killing failure the old Story mode had; it must stay at **0**.
Accuracy (correct / scored) and misses (no answer produced — e.g. an enrichment gap) are secondary.

## Scoring

Each field is one of:

| Status | Meaning |
|---|---|
| `correct` | every value the key lists was produced, and **nothing else** |
| `missed` | no answer was produced, or only some of the key's values were |
| `wrong` | an answer was produced that the key does not list — **even if the right value is also present** |

The last rule matters: a spurious extra victim or C2 next to the right one is a false accusation, so
it counts as confidently wrong. (An earlier version scored it `correct`, which meant a regression that
added spurious answers could never trip the gate.)

`user.account` is scored against the sign-in **on the victim host** only, so the same account being
signed in on some other machine cannot make a wrong attribution look correct. A key may list several
C2s; all are scored. MACs are compared as bare hex (separator style is not a difference) and hostnames
by their machine label (the DNS suffix is not).

## Layout

```
eval/
  cases/<case-id>/
    expected.yaml   # ground truth from the exercise's answer key (committed)
    case.yaml       # pcap name, where to get it, and its sha256 (committed; the pcap is NOT)
  run_eval.py       # runner + scorer
  test_run_eval.py  # tests for the scoring semantics (no stack needed)
  requirements.txt  # PyYAML
  scorecard.md      # latest results, human-readable (committed — trend shows in git)
  scorecard.json    # latest results, structured (committed; carries no per-run ids)
  pcaps/            # local captures (gitignored — large & malware-adjacent)
```

## Running

Needs a running stack (this is a dev/CI-time tool over HTTP — **not** part of the offline runtime) and
PyYAML: `pip install -r eval/requirements.txt`.

```bash
python3 eval/run_eval.py                    # score every case already analyzed on the server
python3 eval/run_eval.py --upload-missing   # upload a local pcap first if the server has none
python3 eval/run_eval.py --out-dir /tmp/x   # write the scorecard elsewhere (a scratch run)
python3 eval/test_run_eval.py               # the scoring tests; no stack needed
```

A case's capture is resolved as: an analyzed file of that name on the server (newest completed one) →
else, with `--upload-missing`, a local copy in `eval/pcaps/` or `backend/target/ctf-demo/` → else the
case is reported `pcap_unavailable`. **The runner does not download anything**: `case.yaml`'s
`source_url` is where a person gets the capture. Its `sha256` *is* enforced — a local capture is
checked against it before upload, so a different file cannot be silently scored against the key. A
file already on the server is matched by name only.

**Exit codes:** `0` all cases scored, nothing wrong · `1` something confidently wrong · `2` the run was
incomplete (a case was skipped or errored). An incomplete run does **not** rewrite the scorecard, so
a partial or empty run can never overwrite the committed baseline with nothing; `--allow-incomplete`
overrides that. Run it manually or nightly, not on every PR (captures are heavy).

## What a scorecard means

The scorecard records the analysis each case was measured under (e.g. `Suricata on`). This matters: it
reads `/answers`, which is producer-only. The committed baseline (6/7) was measured with Suricata on,
where the C2 and malware come from IDS alerts. The same capture analysed with Suricata **off** scores
lower here (3/7 in a scratch run) because the pivots that recover them (#819, PR #821) run in
`/investigation`, which this harness does not score yet — scoring it is the natural next step once
#821 lands.

## Adding a case

1. `mkdir eval/cases/<case-id>` and write `expected.yaml` from the exercise's **published key** (never
   from TracePcap's own output) and `case.yaml` with the pcap name, `source_url` and `sha256`.
2. Fetch the pcap into `eval/pcaps/` (kept out of git).
3. `python3 eval/run_eval.py --upload-missing` and commit the refreshed `scorecard.*`.

## What is scored today

`victim.ip`, `victim.mac`, `victim.hostname`, `user.account`, `user.real_name`, `malware.family`,
`c2.ip`. As the technique library grows (#819), extend `score_case` in `run_eval.py` (scope, entry
vector, timeline, …). `c2` port/proto are recorded in the key but not scored yet — `/answers` does not
expose them.
