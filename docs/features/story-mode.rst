Story Mode
==========

Story Mode combines **deterministic detectors** with an **LLM narrative
generator** to produce a rich, structured analysis of the network activity
captured in a PCAP file.

It is grounded in TracePcap's :doc:`../architecture/knowledge-layer`: the
deterministic answers to the standard investigation questions (victim,
command-and-control, malware, signed-in user) are shown directly and fed to the
LLM as authoritative ground truth, so the narrative names what the deterministic
layers already established rather than re-deriving a weaker picture from metrics.

Alternatives considered
-----------------------

A good report says why the other candidates aren't the answer. The deterministic checks record the
candidates they tested and ruled out, with the rule and the reason, and the narrator gets them as
their own block, marked as ruled out: it may describe each as an alternative that was considered,
never as a finding. When there are any, the narrative has an **Alternatives considered** section
before its conclusion. Today these are:

- a reputation-listed server (Spamhaus DROP, CINS…) that the suspected-C2 rule tested and didn't
  escalate, with the requirement it failed: the host wasn't talking to a confirmed C2 (or reached it
  before it did), the server was reached by name, or it was reached once rather than in rounds;
- a beacon whose server didn't end up a C2: no rule named it and no known family's check-in was in
  its stream;
- a host that failed to sign in as two to four accounts within ten minutes, short of the five that
  make password guessing.

The same list is on the Overview's Investigation Summary, folded under **Considered and ruled out**,
which also answers "did it even look at that server?".

Requirements
------------

A configured LLM server is required for the narrative and Q&A features (see
:doc:`../configuration/llm-setup`). The deterministic findings panels work
without an LLM.

How Story Generation Works
--------------------------

Story generation is a **two-phase LLM pipeline** preceded by fully
deterministic pre-computation. A new generation always replaces any previously
stored story for the same file.

Phase 0 — Deterministic pre-computation (no LLM)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before any LLM call is made, the backend runs two independent computations
over the **full conversation dataset**:

1. **Detector pipeline** — eight detectors run in sequence and produce a
   typed, severity-sorted list of findings (see `Deterministic Findings`_
   below).
2. **Aggregates** — statistics covering the full dataset are pre-computed:
   coverage counts, top external ASNs, protocol risk matrix, TLS anomaly
   summary, beacon candidates, and unknown-app percentage (see `Aggregates
   Panel`_ below).

Additionally, up to **50 timeline bins** (time-bucketed packet and byte
counts) are fetched from the timeline service to provide temporal context.

Phase 1 — Hypothesis and query generation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The LLM receives a structured prompt containing:

- File and capture metadata (filename, size, packet count, bytes, duration,
  start/end times, total conversation count)
- Protocol breakdown (per-protocol packet count, bytes, and percentage)
- Traffic category breakdown (nDPI category distribution)
- Deterministic findings (up to 20 by default, ordered by severity)
- Full-dataset aggregates (unknown-app %, top external ASNs, protocol risk
  matrix, TLS anomaly summary, beacon candidates)
- Traffic timeline (up to 50 time-window rows)
- Optional analyst-supplied additional context

The LLM's sole job in this phase is to produce up to **5 testable hypotheses**
paired with **structured database queries** to investigate the most suspicious
activity. Each query specifies filters such as ``srcIp``, ``dstIp``,
``dstPort``, ``protocol``, ``appName``, ``category``, ``hasRisks``,
``hasTlsAnomaly``, ``riskType``, ``minBytes``, ``maxBytes``, and ``minFlows``.
Catch-all queries (no filters set) are automatically discarded.

How that query reaches the backend depends on what the inference server
supports, and the difference matters:

**Native tool calling** (default, ``LLM_TOOL_CALLING=auto``). The query is
declared as a ``query_conversations`` tool with all 12 filter fields typed in a
JSON schema, so a server that implements ``tools`` constrains generation to the
real shape. One tool call is one hypothesis with the query that tests it, and
the ``queryRef`` linking them is assigned by the backend rather than written by
the model.

**Free-text JSON** (fallback). Where the server does not implement ``tools``,
rejects them, or ignores them, the same prompts are sent as an ordinary
completion and the model's JSON is parsed as before. This path is not
deprecated — it is what keeps Story Mode working against any OpenAI-compatible
backend. It carries one extra repair: ``minBytes`` and ``maxBytes`` are
per-conversation byte counts, and are silently dropped when ``srcIp`` or
``riskType`` is also present, because models reliably pass an aggregate total
there, which would match no individual conversation. Queries that arrive
through the tool keep their byte bounds, since the schema states the semantics
where the value is generated.

On both paths, the strings models reach for to mean "nDPI could not identify
this" (``UNKNOWN_APP``, ``unknown``, ``null``, blank) are mapped to an
"app is null" match — a schema constrains a field's type, not its vocabulary.

Phase 2 — Narrative generation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each query from Phase 1 is executed against the database. Up to **10
conversations** (sorted by total bytes descending) are returned per query as
evidence. The LLM then receives everything from Phase 1 **plus** the
investigation results and writes the final narrative.

If Phase 1 fails for any reason (e.g. LLM error, context-length exceeded),
the pipeline falls back to generating the narrative directly from the
deterministic findings without investigation steps.

Context-length retry
~~~~~~~~~~~~~~~~~~~~

If the LLM rejects the prompt due to context length, the UI presents the
auto-built prompt for the analyst to trim before resubmitting. On retry, the
edited prompt is sent directly to the LLM (Phase 1 is re-run to preserve
investigation steps, but the narrative prompt itself is not rebuilt).

Output-truncation handling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each reply's budget is what the model's context has left after the prompt
(under ``LLM_MAX_TOKENS`` when that is set). The prompt's size is a deliberate
overestimate, so when a reply is cut off (a ``finish_reason`` of ``length``) and
the server's own count of the prompt leaves clearly more room, it is asked once
more with that. A server that refuses the budget and names its limit is asked
again within it. If the reply is still cut off, generation fails deliberately
with a clear ``OUTPUT_TRUNCATED`` error, saying whether the cap or the context
ran out and what to change, rather than letting the truncated JSON surface
later as a cryptic parse error. This is
distinct from the *prompt*-too-large case above, which is caught before the call.

Known analysis limitations (embedded in every prompt)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The LLM is explicitly told the following constraints at generation time:

- Packet payloads and HTTP bodies are not available.
- DNS query names and TLS SNI are not captured.
- Benign (non-risk) conversations are not individually listed.

These limitations also bound what the LLM can reliably state in its output.

The Story Page
--------------

The Story tab is laid out as an investigation, read top to bottom, with the
questions and answers beside it:

- **Where the investigation stands** comes first, summary first (see
  :doc:`../architecture/investigation-framework`). A line first says what the
  capture can show: where it was taken, how complete it is and how long it spans
  ("On a honeypot or sensor (192.168.100.28) · inferred · complete · 24 h").
  Where it was taken is inferred from who talks to whom, so *Why · change* opens
  the reasons, and lets you set it yourself or add evidence toward one answer.
  A host that reads as a honeypot gets a line of its own ("198.51.100.45 is a
  Dionaea honeypot · inferred, 95%"), and its *Why · change* lists the signals:
  the signatures it matched (a stock banner or certificate) and how it behaves.
  You can mark it *Not a honeypot*, or add evidence either way. Any host can be
  marked from its details drawer too (*Identity evidence*, under *Honeypot*),
  including one the signatures missed, such as a high-interaction honeypot.
  A honeypot changes the answers it touches: it is never the victim, a file it
  fetched is reported as attacker tooling it caught, and the hosts that reached it
  answer *Scanner* ("7 hosts … reached the Cowrie honeypot …: a decoy has no real
  users, so this is scanning or an attack").
  Then one sentence and one bar count the investigation's categories by status:
  "Nothing is concluded yet. 17 are still open and 4 can't be seen in this
  capture." Under it:

  - **Answered**: each answer with its grade and confidence.
  - **Worth a look next**: the open categories, those with traffic in this capture
    first, each linking to that traffic's conversations. Three show, and the rest
    open with *and N more open*.
  - **Ruled out** and **Not observable** fold away, each category with why ("no SMB
    or DCE-RPC in this capture", "happens on the host, and rarely shows on the
    wire").
  - **Show all** opens every category with its status, by axis: capture context,
    hosts and activities (with each ATT&CK tactic id).

  It needs no LLM, so it shows before a story is written too.
- **The story** follows: the summary, then *What happened* as a timeline of
  events (suspicious and critical ones marked with an amber or red edge), then
  the rest of the narrative (anomalies, the conclusion) under its own headings.
- **Ask about this capture** stays open in a column on the right, as tall as the
  window allows: the conversation scrolls inside it, and the model's suggested
  questions sit as chips just above the question box. On a narrow screen it moves
  below the story.
- **The evidence the story rests on** sits in tabs under it: *Findings*,
  *Traffic intelligence*, *LLM investigation* and *Traffic over time*, each shown
  only when the story produced it. *Findings* lists the most serious first, ten to
  a page, with a search box (a host, a finding type, a word) and a chip per
  severity.

**Regenerate…** opens a dialog for writing the story again, with the optional
additional context and, under *Advanced*, the prompt limits. **How it works**
explains what is sent to the LLM and what is not. Before a story exists the tab
shows those same settings with a **Write the story** button.

What Story Mode Produces
------------------------

Story Mode returns a response containing several components:

Investigation Summary
~~~~~~~~~~~~~~~~~~~~~~~

The **Investigation Summary** (the answers at the top of the Story tab) surfaces the deterministic answers to the
standard investigation questions — **victim**, **command-and-control**,
**malware**, and **signed-in user** — from the :doc:`../architecture/knowledge-layer`,
each labelled with its :ref:`grade <knowledge-grade>` (measured, reported, or
inferred). These are conclusions deterministic checks drew from the evidence, not
the LLM, and they are the ground truth the narrative and Q&A are built on. The
same panel also appears on the Analysis **Overview** tab when a capture has any
such findings, so the key answers are visible without opening Story Mode. When a
capture matches none of the questions (a benign DNS capture, say), the panel shows
an explicit empty state rather than disappearing.

A command-and-control answer that no malware rule named directly carries a chip
saying how it was concluded: **Suspected** for a reputation-listed server that an
already-infected host kept returning to, or **Install chain** for a remote-access
tool planted by a script or download tool fetching a large payload just before.
The info button beside the chip explains the rule and gives this capture's reason.
Answers about an outside server (command and control, remote access, downloads, bulk
transfers) link to the **Conversations** tab filtered to that address.

Deterministic Findings
~~~~~~~~~~~~~~~~~~~~~~

Before the LLM is invoked, a pipeline of **detector algorithms** runs over
the conversation data and produces typed findings. Each finding has a
severity (``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``), a title, a summary,
affected IPs, and numeric metrics. Detectors include:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Detector
     - What it detects
   * - **DetectionRule**
     - One finding per :doc:`detection rule <custom-signatures>` that matched,
       with the rule's own severity and description, and the hosts it matched
       most. It counts the rules in effect: enabled global rules, the capture's
       own, and, when the story is generated with a network picked in
       **Custom detection rules**, that network's own (minus the global rules it switches
       off). The story page says which network's rules it used; pick a
       different network and regenerate to change it.
   * - **NdpiRisk**
     - Surfaces nDPI risk flags as findings, one finding per distinct risk
       type. Severity is determined by the risk type name:

       - ``CRITICAL``: ``possible_exploit_detected``,
         ``binary_application_transfer``, ``clear_text_credentials``,
         ``suspicious_entropy``
       - ``HIGH``: ``suspicious_dns_traffic``, ``dns_suspicious_traffic``,
         ``malicious_sha1_certificate``, ``malformed_packet``
       - ``MEDIUM``: ``self_signed_certificate``, ``obsolete_tls_version``,
         ``weak_tls_cipher``, ``tls_certificate_about_to_expire``
       - ``LOW``: all other risk types
   * - **Beacon**
     - Identifies periodic/beaconing traffic by computing the coefficient of
       variation (CV) of inter-flow intervals. Flows with ≥3 repetitions,
       mean interval ≥1 second, and CV <0.3 are flagged. CV <0.1 →
       ``CRITICAL``; CV 0.1–0.3 → ``HIGH``. Up to 5 beacons are reported,
       sorted by lowest CV (most periodic first).
   * - **TlsAnomaly**
     - Detects self-signed certificates (issuer DN == subject DN), expired
       certificates (not-after < now), and certificates from unknown/untrusted
       CAs. Severity: ``HIGH`` for self-signed/expired; ``MEDIUM`` for unknown
       CA.
   * - **Volume**
     - Two independent checks per source IP:

       1. **Top talker** — flags any host accounting for >40% of total capture
          bytes (``MEDIUM``).
       2. **High outbound volume** — flags any host that sent ≥10 MB across
          its outbound flows (``MEDIUM``; ``HIGH`` if >100 MB).

       If both conditions fire for the same source IP, only the
       higher-severity finding is kept.
   * - **FanOut**
     - Flags hosts that contacted many distinct destination IPs. The minimum
       threshold to trigger a finding is >5 distinct destinations. >50 distinct
       destinations → ``HIGH``; 6–50 → ``MEDIUM``. Pattern is consistent
       with scanning or lateral movement.
   * - **LongSession**
     - Flags individual conversations lasting longer than **15 minutes**.
       >1 hour → ``HIGH``; 15 min–1 hour → ``MEDIUM``.
   * - **UnknownApp**
     - Flags captures where ≥5% of conversations could not be identified by
       nDPI. >30% → ``HIGH``; >10% → ``MEDIUM``; 5–10% → ``LOW``.
   * - **PortProtocolMismatch**
     - Flags nDPI-identified applications running on non-standard ports.
       Always ``HIGH`` severity. Monitored applications and their expected
       ports:

       - DNS: 53
       - HTTP: 80, 8080, 8000, 8888
       - HTTPS: 443, 8443
       - FTP: 20, 21
       - SSH: 22
       - SMTP: 25, 465, 587
       - IMAP: 143, 993
       - RDP: 3389
       - TELNET: 23

Findings are sorted by severity (``CRITICAL`` first) then by detector type
for stable ordering. Up to 20 findings (by default) are included in the LLM
prompt; all findings are returned to the UI regardless.

LLM Narrative
~~~~~~~~~~~~~

The LLM writes a multi-section narrative from the pre-computed findings and
investigation evidence. The output structure is enforced by the system prompt:

- **Narrative sections**: a ``summary`` section first, then ``detail``
  sections per major finding cluster, ending with a ``conclusion`` containing
  recommendations.
- **Highlights**: every ``CRITICAL`` finding must appear as an ``anomaly``
  highlight; ``HIGH`` → ``warning``; ``MEDIUM``/``LOW`` → ``insight``.
- **Timeline events**: ``CRITICAL`` findings → ``critical`` event type;
  ``HIGH`` → ``suspicious``; ``MEDIUM``/``LOW`` → ``normal``.
- **Suggested questions**: exactly 3, specific to the actual findings.

Story Timeline
~~~~~~~~~~~~~~

The timeline events are told in order inside the story, under *What
happened*, each with its time and a marker for suspicious or critical events.

Aggregates Panel
~~~~~~~~~~~~~~~~

Pre-computed statistics over the **full conversation dataset** are displayed
in the **Traffic Intelligence** panel. These are computed independently of
the LLM and reflect all conversations in the PCAP, not just the evidence
sample sent to the LLM.

The panel contains:

- **Coverage banner** — total flows, total packets, percentage of flows
  flagged as at-risk (coloured green/yellow/red at 0%/10% thresholds),
  unknown-app percentage, and TLS anomaly count.
- **Top External Destinations** — up to 7 external ASNs/orgs ranked by
  outbound bytes, with flow count, data volume, and percentage of total bytes.
- **Protocol Risk Overview** — per-protocol breakdown of total conversation
  count vs. at-risk count. A conversation is *at risk* if its ``flow_risks``
  array (populated by nDPI) is non-empty. The progress bar turns red when
  >30% of that protocol's flows are at risk, yellow otherwise.
- **TLS Certificate Health** — aggregate counts of self-signed, expired, and
  unknown-CA TLS flows.
- **Beacon Candidates** — up to 5 flows exhibiting periodic behaviour (CV
  <0.3, ≥3 flows, mean interval ≥1 s), sorted by CV ascending.

The ⓘ icon in the panel header reveals important caveats:

- **Beacon detection** uses the coefficient of variation (CV) of inter-arrival
  times across flows to the same destination. A low CV (< 0.1) suggests highly
  regular, automated traffic. Short captures may produce false positives;
  legitimate software (NTP, telemetry agents) can appear beacon-like.
- **TLS health** is based on certificate issuer metadata (issuer DN, subject DN,
  NotBefore, NotAfter) extracted at analysis time. Certificates are **not**
  re-validated at display time — an expired certificate shown here reflects the
  certificate's own stated expiry date, not a live OCSP/CRL check.
- **ASN / geo data** is enriched via ipinfo.io at analysis time and may not
  reflect recent IP address reassignments.

Interactive LLM Q&A Chat
~~~~~~~~~~~~~~~~~~~~~~~~

The **Ask about this capture** panel beside the story answers follow-up questions, looking things
up with read-only tools (findings, conversations, hosts, address history, DNS lookups, traffic
destinations and over time) and writing Wireshark filters it has checked on the capture. It is
there before the story is written, too. See :doc:`capture-chat`.

Investigation Panel
~~~~~~~~~~~~~~~~~~~

The **Investigation** panel shows the results of Phase 1: the hypotheses the
LLM formed, the structured queries it generated, and the conversation evidence
retrieved for each. Each query returns up to 10 conversations sorted by total
bytes descending. A maximum of 5 queries are executed per generation; queries
with no filters set are skipped automatically.

Privacy
-------

Story generation sends conversation metadata (not raw packet payloads) to your
configured ``LLM_API_BASE_URL``. Use a local LLM to keep this data fully
within your infrastructure.
