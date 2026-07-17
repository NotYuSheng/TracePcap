The Five-Stage Pipeline
=======================

TracePcap is a modular wrapper around a growing suite of functions. The architecture exists so
that new capability is added by **dropping a module into a stage**, not by editing a core. Every
boundary below was admitted under one test:

   *A stage boundary earns its existence only if modules can be added on one side without touching
   the other side.*

Stages follow the order data changes shape — packets → facts → insights → conclusions →
narrative:

.. code-block:: text

   Ingest → Extract → Scan → Adjudicate → Narrate        Present = the read surface over all
              │          │        │
              │          │        └─ exclusive: one adjudicator per question;
              │          │           human annotations enter here, ranked first;
              │          │           "contested" is a legal, displayable outcome
              │          └─ additive: scanners derive insights from facts;
              │             contradiction between facts is itself a finding
              └─ observations with witnesses: append-only, conflict-preserving,
                 graded MEASURED / REPORTED / INFERRED, plus a run manifest

**Determinism is not a stage.** Every stage contains deterministic (D), LLM-driven (L), and
human-annotated (H) capabilities; the tier is tagged per capability. Prefer D — an LLM must earn
its place by doing something determinism cannot, not by being easier to write.

.. contents::
   :local:
   :depth: 2


.. figure:: c4-container.png
   :alt: TracePcap C4 container diagram, backend modules grouped by pipeline stage
   :width: 100%

   Containers and backend stages. Regenerate with
   ``plantuml docs/architecture/c4-container.puml``.


Stage contracts
---------------

Ingest
~~~~~~

Capture in, bytes stored, analysis scheduled. Byte-level plumbing (merge, checksum, retention)
belongs here — including external tools that manipulate captures without reading into them
(``mergecap`` in ``FileServiceImpl``).

*Add a module when:* a new way for captures to arrive or be prepared (windowed ingest, dedup,
capture-quality assessment — truncation, clock skew, one-sidedness — feeding the manifest).

Extract
~~~~~~~

Digs every available fact out of the capture. **Deterministic, and its records are definitive**:
each fact is an *observation with a witness* — what was observed, where (frame/protocol), when,
by which extractor at which version.

Three grades, fixed per fact *type* at schema level:

.. list-table::
   :header-rows: 1
   :widths: 14 50 36

   * - Grade
     - What it is
     - Examples
   * - MEASURED
     - A property of the traffic itself. Nothing "said" it; it was exhibited.
     - byte counts, timestamps, ports, observed TTL, who sent SYN
   * - REPORTED
     - Content asserted by a network party. The assertion *event* is measured; the assertion
       *content* is testimony from an untrusted party.
     - DHCP hostname, NBNS name, HTTP User-Agent, TLS cert subject
   * - INFERRED
     - A third-party tool's judgment — deterministic to run, but heuristic, with known error
       modes.
     - nDPI app identification, Suricata alerts, GeoIP/OUI lookups

Rules:

* **Append-only; no winner-picking at write time.** Two conflicting hostname claims are both
  stored. Conflicts are resolved downstream (Adjudicate) and detected as findings (Scan) — a
  claim erased at write time can never be scanned. ``IpMacObservationEntity`` is the pattern done
  right; ``HostnameResolverService`` (picks a winner by source priority, discards the rest) is the
  pattern done wrong — see :ref:`divergence`.
* **Run manifest.** Every extractor reports its own status per file — ran / failed / partial,
  facts produced, extractor version. Downstream must consult it: "nDPI didn't run" and "nDPI ran
  and couldn't identify" are different states (the #501 bug is exactly this conflation).
  Versioned provenance also enables **backfill**: when an extractor is added or fixed, the
  manifest says exactly which files to re-run.
* **Two sub-kinds.** *Wire extractors* read the capture (``PcapParserService``, ``NdpiService``,
  ``HostnameResolverService``, hostlog extractors). *Reference extractors* join extracted facts
  against bundled reference data (GeoIP, OUI) — they need no pcap access and can backfill after
  the capture has been aged out.
* **Extraction may be lazy.** Session reconstruction and file carving read the pcap on demand;
  they are Extract-stage work triggered late, not exceptions to the rule.
* **The capture caveat.** Even MEASURED facts are definitive about *the capture*, not *the
  network* — drops, truncation, and one-sided flows mean absence of a fact is never evidence of
  absence.

*Add a module when:* there is a protocol or edge case to mine — deliberately the widest surface.
One protocol quirk = one extractor = zero downstream changes. (LLMNR #511, 802.1Q #464, DHCPv6,
Kerberos, SMB, SNMP sysDescr, per-flow entropy #501/#505, JA4 …)

Scan
~~~~

Reads the fact base — **never the pcap** — and derives insights: judgments with confidence and
reasons. Scanners are **additive**: a new scanner never conflicts with an existing one; it just
adds insights.

Rules:

* **Judgment is the boundary.** Deterministic recombination with nothing to contest (timeline
  bins, protocol breakdowns, top-hosts tables) is a *view*, not an insight — views live with
  Present and are never adjudicated.
* **Contradiction scanners are a first-class family.** In this product, fact conflicts are
  findings, not QC noise: ARP spoofing *is* an IP/MAC conflict; impersonation *is* a
  hostname-vs-certificate conflict. Severity follows the grades — two REPORTED facts disagreeing
  is mild; REPORTED contradicting MEASURED is where attacks live.
* **Scope is an attribute, not a stage**: per-capture (beacons, fan-out) or cross-snapshot
  (pattern-of-life, drift, convention learning #507).
* **The loop rule.** Cross-snapshot scanners may consume adjudications (device identity survives
  IP churn only as an adjudicated question), making the pipeline iterative, not a strict DAG. A
  scanner consuming an adjudication treats it as INFERRED **unless human-confirmed** — machine
  conclusions inform but never self-reinforce at full weight (the #507 circularity guard, made
  structural).

*Add a module when:* facts can be combined into a judgment (centrality #503, volumetric z-scores
#505, unknown-traffic characterisation #501, port-scan/exfil detectors, slow beacons #504).

Adjudicate
~~~~~~~~~~

Answers questions with one voice. Where scanners are additive, adjudicators are **exclusive**:
one adjudicator per question ("what is this host?", "what is its name?", "which subnet?"), and
adding a second for the same question is a conflict, not an addition.

Contract: consume competing insights **and human annotations as ranked inputs — human confirmed
first**; weigh by fact grade (measurement beats testimony); produce a winner with confidence
**or an explicitly contested outcome** — contested is legal, displayable, and narratable.
Conclusions are **versioned and revisable**: when underlying facts change, re-adjudication fires —
``staleSince`` is not a bolt-on, it *is* this mechanism.

``ScoreBoard`` (weighted votes → winner + margin confidence) is the working micro-prototype,
currently living only inside device classification. #499's conflicting-identity bug is the
absence of a host-identity adjudicator; #498 ("surface uncertainty") is simply exposing the
adjudication margin.

*Add a module when:* a new question domain needs one voice (host identity #499, hostname #511,
device type with user evidence #506, subnet membership #502).

Narrate
~~~~~~~

Turns insights into prose a human can act on. LLM-driven, always offline-capable
(``LLM_BASE_URL`` → local inference server; no hosted APIs).

Contract: narrators emit **evidence references** with every claim; a deterministic citation
checker verifies the references resolve to real facts. ``InvestigationService``'s
hypothesis → query → evidence loop is halfway to this already.

*Add a module when:* a new narrative product is needed (cross-snapshot stories #504, comparative
"what changed" narratives, report templates).

Present
~~~~~~~

The thin read surface: REST API, views (the no-judgment aggregations from the Scan rule),
rendering, export. **Present consumes adjudications; it never makes them** — see
:ref:`divergence` for where the frontend currently violates this.

*Add a module when:* a new way to see or export what the pipeline already knows (timeline-union
diagrams #510, heatmaps #505, tiered layout #509, evidence export).


The annotation envelope
-----------------------

Annotation is **not a stage** — it is the envelope on everything. A human can annotate at every
altitude: correct an extracted hostname, override a classification, confirm a subnet label,
dismiss a narrative finding. Every fact and every conclusion carries:

.. code-block:: java

   private String origin = "MANUAL";      // MANUAL | AI | CARRIED_FORWARD
   private boolean llmSuggested;
   private boolean confirmedByHuman;
   private LocalDateTime staleSince;      // + staleFields

``NodeRoleEntity`` is the reference implementation: the machine proposes, the human disposes,
provenance is retained, and the label goes stale when the evidence beneath it moves. Human
annotations get their authority at Adjudicate (ranked first), and ``confirmedByHuman`` data is
the **only** kind that feeds back into scanning at full weight.

New annotation surfaces must reuse this shape. Where they have not, the cost is visible: device
classification has no override path at all while ``signatures.yml`` carries a separate,
incompatible one (#506).


A worked example
----------------

*10.0.0.66 DHCP-declares itself "DC-01". The real domain controller is 10.0.0.10.*

.. list-table::
   :header-rows: 1
   :widths: 14 86

   * - Stage
     - What happens
   * - Ingest
     - The capture lands, is checksummed and queued.
   * - Extract
     - The DHCP extractor records the announcement (REPORTED, frame 812). The TLS extractor
       records 10.0.0.10's certificate CN=DC-01 (REPORTED, cryptographically backed). Traffic
       extractors record both hosts' behaviour (MEASURED). All three observations stored,
       append-only — no winner picked. The manifest shows every extractor ran clean.
   * - Scan
     - The identity-conflict scanner sees two hosts claiming one name, one claim contradicting a
       certificate → insight "possible impersonation, HIGH", citing both frames. The traffic
       scanner notes 10.0.0.66's MEASURED behaviour (fresh MAC, client-like pattern) does not
       match a domain controller.
   * - Adjudicate
     - The hostname adjudicator, weighing certificate above DHCP testimony, gives 10.0.0.10 the
       name ``DC-01`` and marks 10.0.0.66 **contested**. If an analyst had pinned 10.0.0.10 as
       the DC, that annotation enters ranked first and widens the margin.
   * - Narrate
     - "10.0.0.66 announced the domain controller's name 12 minutes after joining the network;
       certificate evidence contradicts the claim" — each clause citing frames, references
       verified by the citation checker.
   * - Present
     - The graph renders 10.0.0.66's label as contested (⚠), not as a confident lie. NodeDetails
       lists all three claims with sources.

Under the current code this attack is **invisible**: ``HostnameResolverService`` picks one name
at write time and discards the rest, so the conflict never exists for anything downstream to
find.

The slow-burn beacon (#504) runs the same rails at cross-snapshot scope: one connection per
capture is nothing; facts and manifest persist; a cross-snapshot scanner — consuming adjudicated
device identity per the loop rule — sees the same pair at the same hour across nine snapshots and
emits a periodicity insight no single capture could contain.


Modules by stage
----------------

Twenty backend modules under ``com.tracepcap``, placed by centre of gravity. Tier key:
``D`` deterministic · ``L`` LLM-driven · ``H`` human-annotated.

.. list-table::
   :header-rows: 1
   :widths: 14 22 10 54

   * - Stage
     - Module
     - Tier
     - Notes
   * - Ingest
     - ``file``
     - D
     - Upload, MinIO storage, merge (``mergecap``), lifecycle.
   * - Ingest
     - ``cleanup``
     - D
     - Retention and disposal.
   * - Extract
     - ``analysis``
     - D
     - The 7-stage orchestrator + wire extractors (``PcapParserService``, ``NdpiService``,
       ``TsharkEnrichmentService``, ``SuricataService``, ``HostnameResolverService``) + reference
       extractors (``GeoIpService``). Owns ``analysis.spi``. Lazy extraction:
       ``SessionReconstructionService``.
   * - Extract
     - ``hostlog``
     - D
     - Per-host service-log extractors (DNS, HTTP). ``WebServerLogExtractor`` currently also
       *scans* (the api/web role decision) — see :ref:`divergence`.
   * - Extract
     - ``extraction``
     - D
     - Lazy extraction: file carving. Its read API is Present.
   * - Scan
     - ``hostclassification``
     - D
     - 7 ``DeviceClassificationSignal`` scanners. Contains ``ScoreBoard`` — an Adjudicate
       prototype embedded in a Scan module.
   * - Scan
     - ``story`` *(detectors)*
     - D
     - 8 per-capture scanners: beacon, volume, fan-out, TLS anomaly, unknown app, …
   * - Scan
     - ``monitor``
     - D + H
     - Cross-snapshot scanner (``ChangeDetectionService``, 13 change types); snapshots are
       Ingest-adjacent; baselines are annotations consumed at Scan.
   * - Scan
     - ``subnets``
     - D + L + H
     - Density detection (D); LLM label suggestion (L); manual confirm (H).
   * - Scan
     - ``signatures``
     - D + H
     - User-authored rules (``signatures.yml``) — a data-driven scanner: plugin surface without
       code.
   * - Scan
     - ``reconciliation``
     - D
     - Cross-source identity reconciliation.
   * - Adjudicate
     - ``insights``
     - D + L + H
     - Node roles + ``LabelStalenessService`` — the nearest existing thing to an adjudicator, and
       home of the annotation reference pattern.
   * - Narrate
     - ``story`` *(narrative)*
     - L
     - ``StoryService``, ``InvestigationService``.
   * - Narrate
     - ``tracer``
     - L
     - LLM-assisted conversation tracing.
   * - Narrate
     - ``filter``
     - L
     - NL → display filter. Validates generated filters against the pcap — a grey case, see
       :ref:`divergence`.
   * - Present
     - ``conversation``
     - D
     - Conversation read API; raw-frame export (evidence export, not fact derivation).
   * - Present
     - ``timeline``
     - D
     - Views (time-binned aggregation — no judgment).
   * - Present
     - ``intelligence``
     - D
     - Views (clusters, top hosts, service summaries).
   * - Present
     - ``report``
     - D
     - PDF/report generation.
   * - envelope
     - ``notes``
     - H
     - Free-text annotation.
   * - —
     - ``common``, ``config``
     - —
     - Cross-cutting; depended on by everything, depend on nothing.


Dependency rules
----------------

#. **Feature → analysis, never the reverse** (#416). The pipeline owns ports (``analysis.spi``);
   feature modules implement them.
#. **Cross the boundary through the seam** — ``analysis.spi`` / ``analysis.dto``, never
   ``analysis`` repositories or entities.
#. **No cycles between modules.**
#. **Raw-capture access is confined** to Ingest byte-plumbing, Extract (eager or lazy), and
   evidence export. Everything else reads the database. If a scanner needs new raw data, that is
   a missing extractor — not a licence to shell out.
#. ``common`` and ``config`` are depended on by everything and depend on nothing.

All four are enforced (frozen) by ArchUnit — see :doc:`enforcement`.


.. _divergence:

Known divergence
----------------

Measured against the model above; frozen in the ArchUnit baseline where enforceable. Each entry
is a refactor target, not a shrug.

* **66 class dependencies** bypass ``analysis.spi`` and reach into ``analysis`` repositories or
  entities (rule 2) — down from 757 (757 → 738 in slice 6a, → 687 in 6b, → 529 in 6c, → 66 in 6d).
  Approaching the documented residual: 27 are ``DeviceClassifierService`` (accepted, see below), 10
  are ``extraction``'s cross-module FK, 26 are ``InvestigationService``. Rule 1 holds at **zero**
  violations. **Module cycles: zero** — three were
  eliminated across slices 1 and 3: ``analysis ↔ file`` (listener moved to its consumer),
  ``monitor ↔ insights`` and ``monitor ↔ subnets`` (a ``monitor.spi`` port package —
  ``LabelStalenessCheck``, ``SnapshotRevalidationHook``, ``InsightPresence`` — implemented by
  ``insights``/``subnets``, plus ``NodeRoleChangedEvent`` relocated to ``common.event`` as shared
  vocabulary, since publisher and consumer sit on opposite sides of the Scan/Adjudicate loop).
  Lesson kept for posterity: ArchUnit's cycle enumeration understates until the last cycle is
  gone — ``monitor ↔ subnets`` only surfaced after ``analysis ↔ file`` was fixed.
* **Hostname claims are now conflict-preserving** (slice 4): ``HostnameResolverService`` records
  every claim into ``hostname_claims`` (V33), and ``HostnameAdjudicator`` picks the display winner
  with the old semantics — same winners, but losing claims survive, so #511's identity-conflict
  scanners finally have evidence to read. The adjudicator is hosted in ``analysis`` until a
  dedicated Adjudicate module exists (``analysis`` must not depend on feature modules — frozen
  rule). Contested IPs are counted and logged; surfacing them as findings and UI state is #511's
  work.
* **``WebServerLogExtractor`` mixes stages** — extraction (endpoint logging) and scanning (the
  api/web role decision that #496 flags as broken) in one pass.
* **Run manifest exists for nDPI only** (slice 2): ``extraction_runs`` records
  COMPLETED/FAILED/SKIPPED per file, served through the ``ExtractionManifest`` SPI port, and
  ``UnknownAppDetector`` now reports a skipped/failed run as a ``COVERAGE_GAP`` finding instead
  of *"100% of Traffic Has Unknown Application, HIGH"* (#501). Remaining extractors (tshark
  enrichment, Suricata when it runs, hostname resolution, service logs) are not yet
  instrumented — their absent rows mean "unknown provenance", same as pre-manifest files.
* **Present no longer scans or adjudicates** (#521, resolved). ``networkService.ts`` used to
  compute ``nodeType`` from ports/nDPI (scanning) and ``getNodeColor`` resolved the
  nodeType-vs-deviceType conflict by display precedence (adjudicating) — client-side, on a
  truncated 50-node set, so a host could classify differently depending on what else fit on screen.
  All four functions (``determineRole``, ``finalizeNodeRole``, ``classifyNodeType``,
  ``getNodeColor``'s precedence) are deleted. ``role`` reads ``initiatorIp`` (the MEASURED SYN fact,
  #496); ``nodeType`` is a projection of the adjudicated host identity through one label map, so
  the two taxonomies that both contained "Web Server" (#499) become one — the adjudicator decides,
  the graph renders. Legacy files with classifications but no identities backfill lazily on first
  read of ``GET /host-identities`` (idempotent).
* **The first real adjudicator exists** (slice 5): ``HostIdentityService`` in ``insights`` answers
  "what is this host?" with one voice — human-confirmed node-role labels ranked first, then the
  classification vote (whose runner-up is now persisted so a knife-edge is distinguishable from a
  walkover), with an explicit **contested** outcome listing candidates. Re-adjudication fires on
  ``AnalysisCompletedEvent`` and ``NodeRoleChangedEvent`` (staleness IS re-adjudication, live).
  Served at ``GET /files/{fileId}/host-identities``, and — as of #521 — this is what the graph
  renders: the frontend consumes the adjudication instead of computing its own (closing #499).
* **``insights`` is fully behind the seam** (slice 6b): 34 → **zero**. ``NodeRoleService`` and
  ``LabelStalenessService`` read hosts through ``HostClassificationLookup`` and external orgs
  through the new ``GeoOrgLookup``; ``HostClassificationsController`` reads through the port and
  the new ``IpMacObservationLookup``. Three ports rather than one on purpose — the shapes are
  genuinely different questions (a host's description, an IP's claimants, a peer set's orgs), and
  widening one port to serve all three is how a seam decays back into a repository. Note the split
  *within* ``HostClassificationLookup``: ``ClassifiedHost`` carries the contest (winner + runner-up)
  for adjudication, ``HostFacts`` carries the description for display and prompt context. Logic the
  consumers used to duplicate — splitting the comma-joined ``service_roles`` column, grouping
  observations by IP, filtering blank orgs — now lives in the adapters, which is what makes the
  port's javadoc a promise rather than a suggestion.
* **``hostclassification``'s 27 remaining violations are accepted, not pending.** They are all
  ``DeviceClassifierService.classify``, which *implements* the ``HostClassifier`` port — a port
  whose own signature returns ``HostClassificationEntity``. The class touches the entity because
  the seam hands it over; that is the contract working. The rule matches package names and cannot
  distinguish "reached around the port" from "used the type the port gave you". Clearing them means
  changing what ``HostClassifier`` returns — the entity conceptually belongs to
  ``hostclassification`` but physically lives in ``analysis.entity`` for JPA's sake — which is a
  schema-shaped change, not seam work. Do not "fix" these by rewriting the classifier.
* **The conversation fact base is behind the seam** (slice 6c): 687 → 529. ``tracer`` 56 → 0,
  ``monitor`` 66 → 3, ``extraction`` 49 → 10. Consumers read ~24 distinct fields off
  ``ConversationEntity``, so ``ConversationFacts`` carries **three nested groups rather than 24 flat
  fields** — and the grouping is the fact grades, which fell out of measuring what each module reads
  rather than being imposed: ``FlowIdentity`` (MEASURED — endpoints, bytes, times; read by
  everyone), ``TlsFacts`` (REPORTED — cert subject, JA3, SNI; the fields a host can forge), and
  ``Findings`` (INFERRED — nDPI app, Suricata alerts, risks). One record and one query, though:
  three ports would mean three round-trips over the same row. ``PacketLookup`` *is* separate,
  because the grain differs — folding packets into a conversation would drag thousands of rows
  behind every timeline bin.
* **Two structural reaches that field-level porting cannot close**, both now handled:

  - ``ConversationRepository.buildSpec`` returns ``Specification<ConversationEntity>`` — the entity
    sits in the *caller's signature*, so ``intelligence``/``conversation``/``story`` were coupled to
    it by type, not by field access. The port takes ``ConversationFilterParams`` (already on the
    seam) and keeps the 168-line Specification inside ``analysis``: callers say what they want, not
    how rows are selected.
  - ``ExtractedFileEntity`` holds a JPA ``@ManyToOne`` to ``ConversationEntity``. The FK crosses the
    module boundary *at the schema level*, so no read port removes it — same class as
    ``DeviceClassifierService``, structural rather than lazy. ``extraction``'s residual is this.
* **All four stages are registries** — Extract, Scan, Adjudicate and Narrate each discover their
  own modules, so adding capability is adding one class. Each has a probe module in its tests: one
  class, registered nowhere, touching nothing in ``main``, asserted on by its *output* rather than
  by bean counts. Verified live on real captures::

     Extract     3 extractors  (3 DETERMINISTIC)
     Scan        8 scanners    (8 DETERMINISTIC)
     Adjudicate  1 adjudicator (1 DETERMINISTIC) — questions: host-identity
     Narrate     1 narrator    (1 DETERMINISTIC)

  The contracts differ per stage, because the stages differ:

  - **Extract writes.** ``ExtractionTarget`` carries the *mutable* working set; extractors fill in
    conversations before persistence. The module owns its own enable conditions (Suricata's global
    kill-switch moved out of ``AnalysisService`` onto ``SuricataService``), and the manifest row is
    automatic — an extractor cannot forget, and forgetting is the #501 conflation. ``tshark`` gained
    a manifest row it never had, for free.
  - **Scan reads.** ``ScanContext`` carries *immutable* facts, memoised so eight scanners asking for
    the conversation list read the database once. Additive: a new scanner never conflicts.
  - **Adjudicate is exclusive.** One voice per question — so discovery alone would be the wrong
    contract. ``AdjudicatorRunner`` refuses to start when two modules claim one question, because
    picking by bean order would make the answer change with an unrelated refactor. The
    ``AFTER_COMMIT``/``REQUIRES_NEW`` plumbing that every adjudicator used to copy is written once.
  - **Narrate reads conclusions.** A narrator that judges is a scanner nobody can inspect. Its
    output reaches the UI: ``CoverageNarrator`` is DETERMINISTIC and states what the capture could
    *not* tell us — the section a language model should never write — in front of the LLM's prose.
    Before the registry every section came from one LLM call, because there was only one way in.

  ``Tier`` lives in ``common.stage``: every stage holds all three tiers, and an extractor and a
  scanner answer to the same three words. The D/L/H taxonomy is something the code knows, not a
  table in this document.
* **Scan was the first stage to get its registry** (slice 6d) — *the first slice that built the
  playbook rather than clearing the way for it.* ``FindingsService`` held eight detector fields and eight call
  lines; a ninth detector meant editing it, which is the "edit a core to add capability" this whole
  architecture exists to prevent. It now injects ``List<Scanner>`` and names nobody.

  The blocker was signature drift: the eight detectors had **five different** ``detect(..)``
  signatures between them, so there was no common interface to list-inject — which is *why* no
  registry existed. ``ScanContext`` collapses them into one, memoising its reads so eight scanners
  asking for the conversation list read the database once.

  ``story.spi`` now holds the three types the playbook is built on:

  - ``Scanner`` — ``name()``, ``tier()``, ``scan(ScanContext)``. Every implementation is discovered.
  - ``Tier`` — ``DETERMINISTIC`` / ``LLM`` / ``HUMAN_ASSISTED``, declared by the module itself. The
    D/L/H taxonomy stops being a table in this document and becomes something the code knows.
  - ``ScanContext`` — the facts a scanner may read. Growing it as a new scanner needs a new fact is
    the seam working; a scanner taking a bespoke parameter is not.

  Discovery is Spring ``List<T>`` injection, the pattern ``SnapshotRevalidationHook`` already uses
  (slice 3) — zero new machinery, and reversible: ``Scanner`` is the contract, and how instances are
  found can change without touching a scanner.

  **The definition of done, and how it is enforced**: ``ScannerRegistryTest`` declares a probe
  scanner in a test file, registered nowhere, touching nothing in ``main`` — then asserts on the
  *finding that comes back through* ``FindingsService``. Its first version checked bean counts
  instead, and passed against a ``FindingsService`` whose scanner list had been emptied; that is
  precisely the failure it exists to catch, so it observes output now.
* **``FilterService`` reads the pcap** to validate LLM-generated filters — the one grey case in
  rule 4, baselined rather than blessed.
