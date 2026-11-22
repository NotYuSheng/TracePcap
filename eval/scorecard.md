# Evaluation scorecard

Baseline of TracePcap's **deterministic** conclusions vs. published answer keys (#819, Workstream A). Regenerate with `python3 eval/run_eval.py`.

- Cases scored: **5** of 5
- Correct: **28** / 32 (accuracy 0.875)
- Missed: **4**
- Confidently wrong: **0** ✅

## 2024-07-30-strrat
Analysis: Suricata **on**, nDPI on.

| Field | Status | Detail |
|---|---|---|
| victim.ip | ✅ correct | 172.16.1.66 |
| victim.mac | ✅ correct | 00:1e:64:ec:f3:08 |
| victim.hostname | ✅ correct | DESKTOP-SKBR25F |
| user.account | ✅ correct | ccollier |
| user.real_name | ✅ correct | Clark Collier |
| malware.family | ✅ correct | STRRAT |
| c2.ip | ✅ correct | 141.98.10.79 |

## 2024-08-15-warmcookie
Analysis: Suricata **on**, nDPI on.

| Field | Status | Detail |
|---|---|---|
| victim.ip | ✅ correct | 10.8.15.133 |
| victim.mac | ✅ correct | 00:1c:bf:03:54:82 |
| victim.hostname | ✅ correct | DESKTOP-H8ALZBV |
| user.account | ✅ correct | plucero |
| user.real_name | ✅ correct | Pierce Lucero |
| malware.family | ✅ correct | WarmCookie |
| c2.ip | ✅ correct | 72.5.43.29 |

## 2025-01-22-fake-authenticator
Analysis: Suricata **on**, nDPI on.

| Field | Status | Detail |
|---|---|---|
| victim.ip | ✅ correct | 10.1.17.215 |
| victim.mac | ✅ correct | 00:d0:b7:26:4a:74 |
| victim.hostname | ✅ correct | DESKTOP-L8C5GSJ |
| user.account | ✅ correct | shutchenson |
| user.real_name | — n/a |  |
| malware.family | — n/a |  |
| c2.ip | ◻️ missed | missing: 45.125.66.32, 45.125.66.252 |

## 2026-01-31-lumma
Analysis: Suricata **on**, nDPI on.

| Field | Status | Detail |
|---|---|---|
| victim.ip | ✅ correct | 10.1.21.58 |
| victim.mac | ✅ correct | 00:21:5d:c8:0e:f2 |
| victim.hostname | ✅ correct | DESKTOP-ES9F3ML |
| user.account | ✅ correct | gwyatt |
| user.real_name | ✅ correct | Gabriel Wyatt |
| malware.family | ✅ correct | Lumma Stealer |
| c2.ip | ✅ correct | 153.92.1.49; also, beyond the key (evidenced): 62.72.32.156 |

## 2026-11-10-netsupport
Analysis: Suricata **on**, nDPI on.

| Field | Status | Detail |
|---|---|---|
| victim.ip | ◻️ missed |  |
| victim.mac | ✅ correct | 00:12:f0:e5:17:43 |
| victim.hostname | ✅ correct | DESKTOP-5OMVI3L |
| user.account | ✅ correct | edward.winslow |
| user.real_name | — n/a |  |
| malware.family | ◻️ missed |  |
| c2.ip | ◻️ missed |  |
