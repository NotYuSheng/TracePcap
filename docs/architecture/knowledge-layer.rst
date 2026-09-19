Knowledge Layer
===============

The **knowledge layer** is a shared, agent-consumable representation of everything TracePcap has
concluded about one capture — the entities, the relationships between them, and the findings — that
sits between the adjudicated analysis and the surfaces that present it (Story mode, the Overview,
the Q&A). It exists so that *adding a new source of information reaches every consumer automatically*,
instead of each presenter hand-picking its inputs.

Why it exists
-------------

TracePcap's Extract and Scan stages are extensible by design: an ``Extractor``, a
``DeviceClassificationSignal``, or an ``Adjudicator`` is *discovered and run*, so adding one is adding
one class. That guarantee used to **break at the narrate boundary**. The narrator (Story mode) built
its prompt from a hand-picked handful of lookups and never saw the IDS alerts, the adjudicated
identities, or the node roles — so it named the wrong command-and-control server, missed the malware
family, and missed the signed-in user, even though the deterministic layers already had all three.

A new library could extract correctly and still never reach the analyst. The knowledge layer closes
that gap by giving every consumer one place to read, and every producer one contract to write to.

A blackboard architecture
-------------------------

The design is a **blackboard** (Hearsay-II; Nii, *Blackboard Systems*, 1986): independent *knowledge
sources* contribute to one shared, structured *board*, and **communicate only through the board** —
never by calling one another. That is precisely the "add one class, zero downstream changes"
property, applied across the whole pipeline instead of only within Extract.

.. code-block:: text

   Deterministic analysis        Knowledge board            Deterministic checks     Presentation
   (Extract / Scan / Adjudicate)  (entities, relationships,  (standard questions ->   (Story narrative,
     Suricata, nDPI, host          findings — each graded)     answers)                 Investigation
     classification, Kerberos/          ^        |                    |                  Summary panel,
     LDAP identity, GeoIP ...          |        v                    v                  Overview, Q&A)
            |                    +--- contributors ---+       +--- checks + the LLM ---+
            +------- write ----->|  (auto-discovered) |------>|  agent (one more KS)   |
                                 +--------------------+       +------------------------+

The key consequence: a deterministic check and the LLM agent are *both just knowledge sources*. The
agent reads the board and narrates; it is not privileged, it does not detect, and removing it loses
no facts. The determinism boundary is structural, not a rule to remember.

The board
---------

The artifact model (``com.tracepcap.knowledge.spi``) borrows its shape from STIX (entities /
relationships / observables with confidence) and OCSF/ECS (normalized, categorized findings):

- **Entities** — a ``HOST``, ``USER``, ``EXTERNAL_SERVICE``, or ``MALWARE``, identified by an
  ``EntityRef`` (type + natural key). Attributes are an open bag, so a contributor describes an
  entity however its source allows without a schema change. Two contributors naming the same
  ``(type, key)`` describe the same node — their attributes merge.
- **Relationships** — a typed, directed edge (``signed-in-as``, ``communicates-with``, ``c2-of``),
  carrying its :ref:`grade <knowledge-grade>` and the contributor that posted it.
- **Findings** — a typed, categorized observation (``ids-alert``, …) attached to the entities it
  concerns, with pointers to the raw evidence (conversation ids).

.. _knowledge-grade:

Every artifact carries a **grade** — the same three-way provenance the Extract stage applies:

============  ===========================================================================
Grade         Meaning
============  ===========================================================================
``MEASURED``  the traffic itself exhibited it (a Kerberos AS-REQ principal). Strongest.
``REPORTED``  a party asserted it on the wire (an LDAP display name) — testimony.
``INFERRED``  a tool judged it (an IDS verdict, a device-type vote) — a guess with error modes.
============  ===========================================================================

So a conclusion built from ``MEASURED`` facts outranks one built from ``REPORTED`` or ``INFERRED``
ones, and every surface can show *how directly* something is known rather than asserting certainty.

Knowledge sources
-----------------

All three kinds are auto-discovered Spring beans — adding one is adding one class.

**Contributors** (``KnowledgeContributor``) post *facts* from one library onto the board. Each reads
only through ``analysis.spi`` ports, never another module's repositories or entities. Today:

- ``HostIdentityContributor`` — host and user entities, plus a graded ``signed-in-as`` edge.
- ``IdsAlertContributor`` — Suricata hits as ``ids-alert`` findings, with the external-service and
  malware entities and the ``communicates-with`` / ``c2-of`` edges they imply.
- ``GeoOrgContributor`` — country / ASN / org for the external endpoints that carry an alert.

**Deterministic checks** (``StandardQuestion``) are the primary analysis layer — *not* the LLM. Each
answers one standard investigation question by querying the board and posting an ``Answer`` (a
conclusion, distinct from a finding). Because input and output are both deterministic, each is
unit-testable against a fixture board. Today: victim, command-and-control, malware, signed-in user.
They are deliberately precise — the victim and C2 checks key on the ``c2-of`` edge, not "any host or
external in any IDS alert", so an informational alert never mislabels the domain controller as a
victim or a benign CDN as a C2.

**The agent** is one final, additive knowledge source. The narrator and the Q&A consume the board's
answers as authoritative ground truth (named, never contradicted); the investigation loop is a
ReAct-style tool loop over the capture. The agent narrates and answers ad-hoc questions — it never
detects, and the deterministic layers stand alone without it.

Where it surfaces
-----------------

- ``GET /files/{fileId}/knowledge`` — the assembled board (entities, relationships, findings).
- ``GET /files/{fileId}/answers`` — the deterministic standard-question answers.
- The **Investigation Summary** panel (Story mode and the Overview) renders the answers directly,
  each with its grade.
- Story mode's narrative and Q&A are grounded in the answers (see :doc:`../features/story-mode`).

Extending it
------------

Adding a fact source is adding a ``KnowledgeContributor``; adding an investigation question is adding
a ``StandardQuestion``. Both are discovered and run with no change to any consumer — the narrative,
the panels, and the agent all pick up the new artifacts generically. That is the property the layer
exists to guarantee: a new library is *accounted for* by construction, not by remembering to wire it
into each presenter.
