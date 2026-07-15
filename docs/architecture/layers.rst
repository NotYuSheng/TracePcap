Layers and Modules
==================

TracePcap is a modular wrapper around a set of capabilities at each layer of a fixed pipeline: a
PCAP goes in, and progressively richer derived knowledge comes out. This page defines the layers,
groups each module under one, and tags every capability by **how it produces its answer** —
deterministically, via an LLM, or from human annotation.

It describes the architecture the code is *meant* to have. Where the code has drifted, that is
recorded honestly below and enforced by :doc:`the architecture tests <enforcement>` so the drift
cannot grow.

.. contents::
   :local:
   :depth: 2


.. figure:: c4-container.png
   :alt: TracePcap C4 container diagram, backend modules grouped by pipeline layer
   :width: 100%

   Containers and backend layers. Data flows L1 → L7. Regenerate with
   ``plantuml docs/architecture/c4-container.puml``.


The spine: pipeline stage
-------------------------

Layers follow **the order data flows through the system**, not OSI depth or module names. This
matches how ``AnalysisService`` already documents itself (``Stage 1: Download`` … ``Stage 7: File
extraction``) and is the ordering that actually constrains design: a stage may only depend on what
earlier stages produced.

Determinism is *not* a layer. It is an attribute of an individual capability — most layers contain
deterministic, LLM-driven, and human-annotated capabilities side by side. It is tagged per
capability instead.

.. list-table::
   :header-rows: 1
   :widths: 8 20 72

   * - Layer
     - Name
     - What it does
   * - L1
     - Ingest
     - Accept and store a capture; schedule analysis.
   * - L2
     - Parse
     - Turn packets into structured conversations and packet rows.
   * - L3
     - Enrich
     - Attach protocol, application, risk, geo, and hostname facts to what L2 produced.
   * - L4
     - Classify
     - Decide what each host *is* — device type, service roles, node roles, subnets.
   * - L5
     - Detect
     - Find patterns across a capture or across snapshots — risks, beacons, drift, changes.
   * - L6
     - Narrate
     - Explain findings to a human — stories, insights, investigations.
   * - L7
     - Present
     - Serve it — REST reads, reports, exports.


Modules by layer
----------------

Twenty backend modules under ``com.tracepcap``. Each is assigned the layer where its centre of
gravity sits; a few (notably ``analysis``) span several and are noted.

.. list-table::
   :header-rows: 1
   :widths: 8 22 12 58

   * - Layer
     - Module
     - Tier
     - Notes
   * - L1
     - ``file``
     - D
     - Upload, storage (MinIO), file lifecycle.
   * - L1
     - ``cleanup``
     - D
     - Retention and disposal.
   * - L2
     - ``analysis`` *(pipeline)*
     - D
     - ``PcapParserService`` and the 7-stage orchestrator. Spans L2–L4.
   * - L3
     - ``analysis`` *(enrichment)*
     - D
     - ``NdpiService``, ``TsharkEnrichmentService``, ``SuricataService``, ``GeoIpService``, ``HostnameResolverService``.
   * - L3
     - ``hostlog``
     - D
     - Per-host service logs (DNS, HTTP endpoints) via ``HostServiceLogExtractor``.
   * - L3
     - ``signatures``
     - D + H
     - User-authored YAML detection rules (``signatures.yml``).
   * - L4
     - ``hostclassification``
     - D
     - Weighted-vote device classification; 7 ``DeviceClassificationSignal`` implementations.
   * - L4
     - ``subnets``
     - D + L + H
     - Density-based detection (D), LLM label suggestion (L), manual confirm (H).
   * - L4
     - ``insights``
     - D + L + H
     - Node roles, label staleness. **The reference implementation of the annotation model.**
   * - L4
     - ``reconciliation``
     - D
     - Cross-source identity reconciliation.
   * - L5
     - ``monitor``
     - D
     - Snapshots, baselines, ``ChangeDetectionService`` (13 change types).
   * - L5
     - ``story`` *(detectors)*
     - D
     - 8 detectors: beacon, volume, fan-out, TLS anomaly, unknown app, …
   * - L5
     - ``intelligence``
     - D
     - Clusters, top hosts, service-server summaries.
   * - L5
     - ``timeline``
     - D
     - Time-binned traffic aggregation.
   * - L6
     - ``story`` *(narrative)*
     - L
     - ``StoryService``, ``InvestigationService`` — LLM narrative + investigation loop.
   * - L6
     - ``tracer``
     - L
     - LLM-assisted conversation tracing.
   * - L6
     - ``filter``
     - L
     - Natural-language → display-filter generation.
   * - L6
     - ``notes``
     - H
     - Free-text human annotation.
   * - L7
     - ``report``
     - D
     - PDF/report generation.
   * - L7
     - ``conversation``
     - D
     - Conversation read API.
   * - L7
     - ``extraction``
     - D
     - Carved-file read API.
   * - —
     - ``common``, ``config``
     - —
     - Cross-cutting; depended on by everything, depends on nothing.

**Tier key** — ``D`` deterministic · ``L`` LLM-driven · ``H`` human-annotated.


The three tiers
---------------

Deterministic (D)
~~~~~~~~~~~~~~~~~

Same input, same output, always. Explainable by reading the code. This is the default and the
majority of the system: ``PcapParserService``, ``NdpiService``, ``TsharkEnrichmentService``,
``SuricataService``, ``HostnameResolverService``, ``GeoIpService``, the 7 classifier signals, the 8
story detectors, ``ChangeDetectionService``, ``SubnetService``.

**Prefer this tier.** An LLM should earn its place by doing something determinism cannot — not by
being easier to write.

LLM-driven (L)
~~~~~~~~~~~~~~

Eight services depend on ``LlmClient``:
``StoryService``, ``InvestigationService``, ``NetworkInsightService``, ``SnapshotInsightService``,
``SubnetLabelSuggestionService``, ``ConversationTracerService``, ``FilterService``,
``NodeRoleService``.

All inference must stay **offline-capable** — ``LLM_BASE_URL`` points at a local inference server.
No hosted APIs (see :doc:`../getting-started/offline-deployment`).

The characteristic risk of this tier is **circularity**: an LLM labelling data that later trains or
informs the thing that produced it. Keep LLM output on the annotation side of the boundary, or gate
it behind human confirmation.

Human-annotated (H)
~~~~~~~~~~~~~~~~~~~

Facts a human asserted, and the record of who asserted them. ``NodeRoleEntity`` is the reference
implementation and the pattern to copy:

.. code-block:: java

   private String origin = "MANUAL";      // MANUAL | AI | CARRIED_FORWARD
   private boolean llmSuggested;
   private boolean confirmedByHuman;
   private LocalDateTime staleSince;      // + staleFields

That is the full **AI-assisted human annotation** model: the machine proposes, the human disposes,
provenance is retained, and the label goes stale when the evidence beneath it moves. Also applied
by ``SubnetDefinitionEntity`` (``source`` = MANUAL|AUTO, ``confirmed``) and
``BaselineDefinitionEntity``.

**New annotation surfaces should reuse this shape rather than invent one.** Where they have not,
the cost is visible: device classification has no override path at all, while ``signatures.yml``
carries a separate, incompatible one (#506).


The analysis pipeline
---------------------

``AnalysisService.analyzeFile`` runs seven stages in order:

.. code-block:: text

   Stage 1: Download                          ← L1
   Stage 2: PCAP parse                        ← L2
   Stage 3: nDPI + tshark enrichment          ← L3
   Stage 4: Signatures, device classification, geo-IP   ← L3/L4
   Stage 5: Persist analysis result
   Stage 6: DB inserts (conversations + packets)
   Stage 7: File extraction                   ← via FileExtractionStage port

Ordering is load-bearing, not incidental. Service-log extraction runs *before* classification so a
host's observed roles can drive its device type (a DNS responder → ``DNS_SERVER``). Stage 7 is a
post-persist hook gated on ``file.isEnableFileExtraction()``.

The stages are currently expressed as **comments inside one long method**, not as composable units.
Decomposing them is tracked in #512.


Extension seams
---------------

Add capability by implementing a seam, not by editing the core. Each is auto-discovered by Spring.

.. list-table::
   :header-rows: 1
   :widths: 30 12 58

   * - Seam
     - Impls
     - To add a capability
   * - ``DeviceClassificationSignal``
     - 7
     - ``@Component`` voting into ``ScoreBoard``; new device types need no core change (types are strings).
   * - ``story.service.detector.*``
     - 8
     - ``@Component`` returning ``List<Finding>``; register in ``FindingsService.detectAll``.
   * - ``HostServiceLogExtractor``
     - 2
     - ``@Component`` running one tshark pass, persisting its own rows, reporting roles per IP.
   * - ``SignatureApplier``
     - 1
     - Port owned by ``analysis``; implemented by ``signatures``.
   * - ``HostClassifier``
     - 1
     - Port owned by ``analysis``; implemented by ``hostclassification``.
   * - ``FileExtractionStage``
     - 1
     - Post-persist hook; implemented by ``extraction``.

The ``DeviceClassificationSignal`` javadoc states the intent for all of them:

   *"This is the extension seam for the classifier: DeviceClassifierService injects every
   DeviceClassificationSignal bean and runs them all, so adding a new signal (or a new device type
   to vote for) is just adding a @Component — no change to the classifier core."*


Dependency rules
----------------

#. **Feature → analysis, never the reverse.** Established by #416. The ingest pipeline owns ports
   (``analysis.spi``); feature modules implement them.
#. **Cross the boundary through the seam.** Other modules consume ``analysis`` via ``analysis.spi``
   and ``analysis.dto`` — never its repositories or JPA entities.
#. **No cycles between modules.**
#. ``common`` and ``config`` are depended on by everything and depend on nothing.

Current module dependencies:

.. code-block:: text

   analysis       → common, file                       ⚠ cycle with file
   conversation   → analysis, common, file
   extraction     → analysis, common, file
   file           → analysis, common, config           ⚠ cycle with analysis
   filter         → common, file, story
   hostclassification → analysis, config, file
   hostlog        → analysis, file
   insights       → analysis, common, config, monitor, notes, story   ⚠ cycle with monitor
   intelligence   → analysis, hostlog
   monitor        → analysis, common, file, insights, intelligence    ⚠ cycle with insights
   reconciliation → analysis, config, file
   report         → analysis, common, extraction, file, story
   signatures     → analysis
   story          → analysis, common, config, file, timeline
   subnets        → analysis, common, monitor, story
   timeline       → analysis, common, file
   tracer         → analysis, common, story


Known drift
-----------

Measured, not estimated. These are frozen in the ArchUnit baseline — see :doc:`enforcement`.

**Rule 2 is widely bypassed — 755 class dependencies** reach into ``analysis.repository`` or
``analysis.entity`` from outside ``analysis``, against a single import of the ``analysis.spi``
package that exists to prevent exactly this. Every one pins the ingest pipeline in place: it cannot
change without touching its consumers.

**Two cycles, 71 dependencies:**

* ``monitor ↔ insights`` — each imports the other's repositories and entities. ``monitor →
  insights`` already communicates via an event (``NodeRoleChangedEvent``), so the decoupling
  pattern is present and simply not applied consistently.
* ``analysis ↔ file`` — a single narrow edge: ``file`` needs only ``AsyncAnalysisService``. The
  natural first candidate for an event or a port.

**Rule 1 holds — zero violations.** #416's core invariant survived. It is frozen anyway so a
regression reports precisely rather than as an anonymous slice failure.

**Mass concentration.** ``analysis`` is 6,774 LOC across 40 files, roughly double the next module
(``story``, 3,174). Largest classes: ``SessionReconstructionService`` (1,416),
``ReportService`` (1,407), ``FileExtractionService`` (1,061), ``StoryService`` (1,032). Size alone
is not a defect — these may be cohesive — but ``analysis`` is where work lands by default because
nothing tells contributors where else to put it. That is what this document is for.
