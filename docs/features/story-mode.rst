Story Mode
==========

Story Mode combines **deterministic detectors** with an **LLM narrative
generator** to produce a rich, structured analysis of the network activity
captured in a PCAP file.

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
Catch-all queries (no filters set) are automatically discarded. Note that
``minBytes`` and ``maxBytes`` are per-conversation byte counts and are silently
ignored by the backend when ``srcIp`` or ``riskType`` is also present in the
same query.

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

Known analysis limitations (embedded in every prompt)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The LLM is explicitly told the following constraints at generation time:

- Packet payloads and HTTP bodies are not available.
- DNS query names and TLS SNI are not captured.
- Benign (non-risk) conversations are not individually listed.

These limitations also bound what the LLM can reliably state in its output.

What Story Mode Produces
------------------------

Story Mode returns a response containing several components:

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

A visual timeline is derived from the narrative output, showing key events
in chronological order.

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
~~~~~~~~~~~~~~~~~~~~~~~~~

After the narrative is generated, a **chat panel** allows follow-up questions
about the PCAP. The LLM answers using the full story JSON as context and
returns 3 suggested follow-up questions with each answer.

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
