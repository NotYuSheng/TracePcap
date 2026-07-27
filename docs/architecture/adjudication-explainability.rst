Adjudication: Explainability, Override & Evidence
==================================================

Every adjudicated conclusion in TracePcap must be able to answer three questions from an analyst,
uniformly, no matter which module produced it:

   1. **Why did you conclude this?** — the ranked evidence, with human-readable reasons.
   2. **I disagree — let me say what it is.** — a first-class human override that outranks the machine.
   3. **You're missing something — here's more evidence.** — analyst-appended evidence that
      re-enters adjudication as just another weighted signal.

And, because the deployment is authenticated (Keycloak JWT), a fourth, cross-cutting requirement:

   4. **Who said so, and when?** — every human action (override, evidence, dismissal) carries an
      actor and a timestamp. An **audit trail**, not an anonymous edit.

Today these exist only partially, and where they exist they are *per-question and ad-hoc*. This
document defines a single contract on the ``Adjudicate`` stage so that a **new adjudicated question
is added by dropping in one module**, and it inherits explainability, override, evidence-append and
audit for free — the same "drop a module into a stage" test the five-stage pipeline is built on.

.. contents::
   :local:
   :depth: 2


Where we are (the problem)
--------------------------

Three adjudicated questions exist, reached by three unrelated mechanisms:

.. list-table::
   :header-rows: 1
   :widths: 20 26 26 28

   * - Question
     - Explainability
     - Human override
     - Modularity
   * - ``host-identity``
     - Partial — ``candidates[]`` scores in a tooltip; the *reasons* computed in ``ScoreBoard``
       are **discarded** before they reach the DTO.
     - Indirect — only by relabelling the *node-role*; and via a **separate** classification popup.
     - On the ``Adjudicator`` seam. Good.
   * - ``hostname``
     - None surfaced — losing claims are logged, never shown per host.
     - Only by injecting a ``SOURCE_MANUAL`` claim, for which **no UI exists**.
     - **Not even an** ``Adjudicator`` **bean** — a plain ``@Component`` the pipeline calls directly.
   * - ``node-role``
     - Good — AI-suggest / accept / discard / manual / stale.
     - Full edit workflow.
     - A separate subsystem, not reused by the others.

Four defects follow:

- **Reasons exist but are thrown away.** ``ScoreBoard.reasonsFor()`` already records *why each type
  scored*. ``ClassifiedHost`` deliberately carries no reasons, so the "why" dies inside the Scan
  stage and never reaches the analyst.
- **Override is smuggled.** Identity is overridden through node-role; hostname through a magic
  source constant. There is no single "I disagree, here's the answer" affordance.
- **Evidence-append is absent everywhere.** Nothing lets an analyst contribute a fact the capture
  didn't reveal ("this box is a domain controller — I confirmed it out-of-band").
- **No audit.** No entity records *who* confirmed a node-role, let alone who overrode an identity.
  ``confirmedByHuman`` is a boolean with no name behind it.


The contract
------------

The ``Adjudicator`` interface is extended so a verdict is **self-explaining**, and the runner is
backed by two **shared, question-agnostic** tables that any adjudicator reads without knowing they
exist for anyone else.

Verdict carries its reasons
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An adjudicator stops emitting a bare winner and emits a ``Verdict``:

.. code-block:: text

   Verdict
     primaryLabel   the one answer
     basis          HUMAN | MACHINE | REPORTED       (grade of the winning evidence)
     confidence     0–100
     contested      true ⇒ carry the candidates, do not assert the winner
     candidates[]   Candidate{ label, source, score, reasons[] }   ← reasons[] is the new part

``reasons[]`` is the *human-readable* trail — ``"MAC OUI is Cisco (+40)"``, ``"listens on 53/udp
(+30)"``. It is the same list ``ScoreBoard`` already builds; the change is that it now survives from
Scan into Adjudicate and out to the DTO instead of being logged and dropped.

**Rule:** a machine verdict with no reasons is a bug. Explainability is not optional decoration — it
is part of what "answer a question" means on this stage.

Two shared tables, keyed by the question
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Override and evidence are **not** re-implemented per adjudicator. They live in two tables keyed by
the tuple ``(question, file_id, entity_key)`` — the same coordinates every adjudicator already works
in — so a new adjudicator inherits both by doing nothing:

.. code-block:: text

   human_override        one row = "a human's final answer for this question about this entity"
     question            "host-identity", "hostname", …   (the Adjudicator.question() key)
     file_id, entity_key which host/IP/MAC
     label               the human's answer  (outranks everything the machine produced)
     rationale           free text: why they overrode
     actor               ← WHO (JWT subject / preferred_username; "system" when auth is off)
     created_at          ← WHEN

   manual_evidence       append-only: analyst-contributed signals that re-enter adjudication
     question, file_id, entity_key
     label               which candidate this evidence supports
     weight              how strongly (bounded; a human signal is strong but not infinite)
     reason              shown verbatim in the reasons[] trail, tagged "analyst-provided"
     actor, created_at   ← audit, same as above

Adjudication precedence becomes uniform and explicit, highest first:

.. code-block:: text

   1. human_override        present ⇒ that IS the answer. basis HUMAN, confidence 100, never contested.
   2. machine vote          ScoreBoard(observed signals + manual_evidence rows as weighted inputs)
   3. contested             machine margin below threshold ⇒ carry candidates, assert nothing

Manual evidence does **not** silently become the answer — it enters the *vote* as a strong signal
and is visible in the reasons trail. Only an explicit **override** short-circuits the machine. This
keeps the honest-disagreement property: an analyst who adds a leaning signal still sees a contest if
the machine genuinely disagrees, rather than having their thumb on the scale hidden.

The audit trail
~~~~~~~~~~~~~~~~~

``actor`` + ``created_at`` on both tables is the trail. The actor is resolved once, centrally, from
the security context:

- **Auth on** (``tracepcap.auth.enabled=true``): the JWT ``preferred_username`` (falling back to
  ``sub``). Never trust a client-supplied "who" field — it comes from the token, server-side.
- **Auth off** (the default): there is no principal. The actor is recorded as ``"system"`` and the
  UI renders "unattributed". The feature must not require auth to function — it degrades, it does
  not break.

A single ``CurrentActor`` component owns this resolution so no adjudicator, controller or service
reaches into ``SecurityContextHolder`` itself. ``node-role``'s ``confirmedByHuman`` boolean is
extended the same way (``confirmedBy`` actor), so the existing override channel joins the trail
rather than staying anonymous.


Modularity: adding a new adjudicated question
---------------------------------------------

The test this whole document must pass: *a new adjudicated question is one new class plus its
signals — nothing else.* After this change, adding e.g. ``"os-family"`` means:

1. Write an ``OsFamilyAdjudicator implements Adjudicator`` — declare ``question()`` = ``"os-family"``
   and ``tier()``. Build its ``Verdict`` from whatever signals it wants, including
   ``manual_evidence`` rows for its own question (read through the shared port).
2. That's it. The ``AdjudicatorRunner`` discovers it, enforces exclusivity, and re-runs it on new
   facts and on annotation changes. Override, evidence-append, audit and the entire frontend panel
   work with **zero** new UI or endpoints — they are keyed by ``question()``, which the new module
   already declares.

Signals within an adjudicator stay modular too: a contributor is a small unit that votes into a
``ScoreBoard`` with a reason string (the existing ``DeviceClassificationSignal`` shape). Analyst
evidence is *itself* modelled as one such contributor reading the ``manual_evidence`` table, so the
human and the machine feed the same vote through the same door.


Frontend: one panel, on the verdict alone
------------------------------------------

The bespoke blocks in ``NodeDetails`` (the Identity ``<dd>``, the ``NodeClassificationPopup``)
collapsed into **one** reusable component, rendered for the adjudicated question:

.. code-block:: text

   <AdjudicationPanel question="host-identity" fileId entityKey />

Given a question key it renders, uniformly:

- **Verdict badge** — winner, or "⚠ contested" carrying the candidates.
- **Why** — the ranked candidates with their scores and ``reasons[]``.
- **Override** — "I disagree" → label + rationale, attributed to the current actor on save.
- **Add evidence** — append a weighted supporting signal that re-enters the vote.
- **Trail** — who overrode / added evidence, and when.

**Facts are not sub-verdicts.** An earlier iteration also stacked per-axis panels
(``host-hardware`` / ``host-service`` / ``host-behaviour``) under the identity, each with its own
override and evidence affordance. That blurred the model: the axes are *measured facts* (OUI
manufacturer, TTL, confirmed service roles, who-initiated counts), not competing conclusions an
analyst can disagree with — and their evidence rows were never read back into any vote. The axes now
render as read-only fact rows beneath the Identity panel; all analyst input (override + evidence)
lives on ``host-identity``, where it actually feeds the vote. The vestigial per-axis backend
plumbing is tracked for removal in issue #536.


Slices
------

Delivered in order; each slice is shippable and leaves the tree green.

.. list-table::
   :header-rows: 1
   :widths: 8 42 50

   * - #
     - Slice
     - Why first / depends on
   * - 1
     - **Reasons survive Scan → Adjudicate.** Persist ``ScoreBoard`` reasons with the winner; carry
       them through ``ClassifiedHost``/lookup port into ``HostIdentityDto.candidates[].reasons``.
     - Pure "why", no new tables. Unblocks the immediate question and is a prerequisite for the panel.
   * - 2
     - **``CurrentActor`` + audit fields.** Central actor resolution; add ``confirmedBy`` to
       node-role. No behaviour change, just attribution.
     - Small, isolated, needed by every write in slices 3–4.
   * - 3
     - **Shared ``human_override`` table + generic override endpoint**, wired into
       ``HostIdentityService`` precedence (override ranks above node-role above machine). One
       controller keyed by the ``question`` path variable serves every question.
     - The core "I disagree" affordance, uniform across questions.
   * - 4
     - **``manual_evidence`` table + append endpoint**, modelled as a ``ScoreBoard`` contributor.
     - Depends on 1 (reasons trail to show it in) and 3 (precedence).
   * - 5
     - **``<AdjudicationPanel>``** replaces the three bespoke blocks; ``NodeDetails`` enumerates
       questions from the API.
     - Depends on 1–4 being live behind a stable read shape.

Non-goals for this pass: per-user data scoping (data stays shared across authenticated users, as
today); versioned override history beyond append-only rows; adjudicating questions outside the host
domain.

**Deferred — ``HostnameAdjudicator`` promotion.** ``HostnameAdjudicator`` today is a synchronous,
in-analysis component (``adjudicate(Collection<Claim>)`` returning winners consumed inline), not a
persisting ``Adjudicator`` on the ``adjudicate(UUID fileId)`` seam. Promoting it reworks the analysis
write path, so it is intentionally held back — the generic override table already keys by
``question``, so ``"hostname"`` gains override, evidence and audit the moment the promotion lands,
with zero new infrastructure. The seam is ready; the promotion is a separate, self-contained change.
