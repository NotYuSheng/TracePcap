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
     - Surfaces nDPI risk flags directly as findings.
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
     - Flags top talkers that account for >40% of total capture traffic
       (``MEDIUM``) and any host that sent ≥10 MB outbound (``MEDIUM`` or
       ``HIGH`` if >100 MB), as potential data exfiltration indicators.
   * - **FanOut**
     - Flags hosts that contacted many distinct destination IPs. >50 distinct
       destinations → ``HIGH``; fewer → ``MEDIUM``. Pattern is consistent
       with scanning or lateral movement.
   * - **LongSession**
     - Flags individual conversations lasting longer than **15 minutes**.
       >1 hour → ``HIGH``; 15 min–1 hour → ``MEDIUM``.
   * - **UnknownApp**
     - Flags captures where ≥5% of conversations could not be identified by
       nDPI. >30% → ``HIGH``; >10% → ``MEDIUM``; 5–10% → ``LOW``.
   * - **PortProtocolMismatch**
     - Flags nDPI-identified applications running on non-standard ports (e.g.
       DNS on a port other than 53, HTTP on a port other than 80/8080, etc.).
       Always ``HIGH`` severity.

LLM Narrative
~~~~~~~~~~~~~

The LLM receives a structured summary of conversation metadata (IPs, ports,
protocols, applications, risk flags, timestamps, geolocation, custom signature
matches) and produces a multi-section narrative describing the network
activity, notable events, and anomalies.

Story Timeline
~~~~~~~~~~~~~~

A visual timeline is derived from the narrative output, showing key events
in chronological order.

Aggregates Panel
~~~~~~~~~~~~~~~~

Pre-computed statistics over the full conversation dataset are displayed in
the **Aggregates** panel — top talkers, protocol breakdown, risk counts, etc.
These are computed independently of the LLM and reflect **all conversations**
in the PCAP, not just the evidence sample sent to the LLM.

The ⓘ icon in the Aggregates panel header reveals important caveats:

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
about the PCAP. The LLM answers using the PCAP metadata as context.

Investigation Panel
~~~~~~~~~~~~~~~~~~~

The **Investigation** panel shows LLM-directed investigation steps:
hypotheses the LLM formed, structured queries it ran against the conversation
data, and the conversation evidence it retrieved to support each hypothesis.

Privacy
-------

Story generation sends conversation metadata (not raw packet payloads) to your
configured ``LLM_API_BASE_URL``. Use a local LLM to keep this data fully
within your infrastructure.
