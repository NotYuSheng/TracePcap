# Evaluation scorecard

Baseline of TracePcap's **deterministic** conclusions vs. published answer keys (#819, Workstream A). Regenerate with `python3 eval/run_eval.py`.

- Cases: **1**
- Correct: **6** / 7 (accuracy 0.857)
- Missed: **1**
- Confidently wrong: **0** ✅

## 2024-07-30-strrat
| Field | Status | Detail |
|---|---|---|
| victim.ip | ✅ correct | 172.16.1.66 |
| victim.mac | ✅ correct | 00:1e:64:ec:f3:08 |
| victim.hostname | ✅ correct | DESKTOP-SKBR25F |
| user.account | ✅ correct | ccollier |
| user.real_name | ◻️ missed |  |
| malware.family | ✅ correct | STRRAT |
| c2.ip | ✅ correct | 141.98.10.79 |
