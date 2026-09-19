# Investigation evaluation harness (#819, Workstream A)

Scores TracePcap's **deterministic** conclusions against published answer keys, so the autonomous
investigation work (#819) has a measurable baseline *before* any agent, and so regressions are caught.

The metric that matters is **confidently wrong** — a field where TracePcap produced an answer that
contradicts the key. That is the trust-killing failure the old Story mode had; it must stay at **0**.
Accuracy (correct / scored) and misses (no answer produced — e.g. an enrichment gap) are secondary.

## Layout

```
eval/
  cases/<case-id>/
    expected.yaml   # ground truth from the exercise's answer key (committed)
    case.yaml       # pcap fetch manifest: source_url + sha256 (committed; pcap is NOT)
  run_eval.py       # runner + scorer
  scorecard.md      # latest results, human-readable (committed — trend shows in git)
  scorecard.json    # latest results, structured (committed)
  pcaps/            # local captures (gitignored — large & malware-adjacent)
```

## Running

Needs a running stack (this is a dev/CI-time tool over HTTP — **not** part of the offline runtime).

```bash
python3 eval/run_eval.py                    # score every case that is already analyzed on the server
python3 eval/run_eval.py --upload-missing   # upload a local pcap first if the server has no such file
```

It resolves each case's capture by: an already-analyzed file of that name on the server → else a
local copy in `eval/pcaps/` or `backend/target/ctf-demo/` (with `--upload-missing`) → else it skips
the case and marks it `pcap_unavailable`. Exit code is non-zero if anything is confidently wrong (the
signal a CI gate would use). Run it manually or nightly, not on every PR (captures are heavy).

## Adding a case

1. `mkdir eval/cases/<case-id>` and write `expected.yaml` from the exercise's **published key** (never
   from TracePcap's own output) and `case.yaml` with the pcap `source_url` + `sha256`.
2. Fetch the pcap into `eval/pcaps/` (kept out of git).
3. `python3 eval/run_eval.py --upload-missing` and commit the refreshed `scorecard.*`.

## What is scored today

`victim.ip`, `victim.mac`, `victim.hostname`, `user.account`, `user.real_name`, `malware.family`,
`c2.ip`. As the technique library grows (#819), extend `SCORED_FIELDS` in `run_eval.py` (scope,
entry vector, timeline, …). `c2` port/proto are recorded in the key but not scored yet — `/answers`
does not expose them.
