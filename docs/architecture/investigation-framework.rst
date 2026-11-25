Investigation Framework
=======================

.. note::

   **Status: in progress.** The categories and their catalogue are built (phase 1): every category,
   the questions that answer it and the traffic they read are served at
   ``GET /api/v1/investigation-categories``. The coverage statuses, capture context and honeypot
   detection are not built yet. See `Delivery plan`_.

TracePcap should judge every capture against **one fixed set of categories**, and say for each one
whether it was *answered*, *ruled out*, still *open*, or *not observable* in this capture. The
categories come from established frameworks (MITRE ATT&CK for activities, the Diamond Model for
roles) plus a third axis for what the capture itself can show. Honeypot detection is the first new
category, as a host role.

Why
---

The :doc:`knowledge layer <knowledge-layer>` answers nine standard questions: ``victim``,
``signed-in-user``, ``malware``, ``c2``, ``downloads``, ``data-transfer``, ``remote-access``,
``lateral-movement`` and ``kerberos-attack``. Each is a ``StandardQuestion`` class with a free-text
key. They were added one at a time, mostly to match what the malware-traffic-analysis.net answer
keys ask (see the walkthroughs under *Demos*).

The cost is that **gaps don't show**. A question that doesn't exist says nothing, so "checked, found
nothing" and "never looked" read the same. The *Worth a look* card on the
:doc:`Overview </features/analysis-overview>` already marks each question Answered, Ruled out or
Open, but only for the questions that happen to be written.

Honeypots show the problem well. No question asks what a host *is*, beyond victim or C2, yet a
honeypot changes how every other answer should be read (see `Honeypots`_).

Frameworks
----------

No one framework covers everything. ATT&CK gives the activity list, the Diamond Model gives the
entity roles, and a capture's own limits need a third axis that neither has.

.. list-table::
   :header-rows: 1
   :widths: 18 24 28 30

   * - Framework
     - What it organises
     - What we take
     - What it lacks for a pcap
   * - `MITRE ATT&CK <https://attack.mitre.org/>`_ tactics
     - Attacker goals: 14 tactics, Reconnaissance to Impact
     - The activity axis, and stable ids (``TA0011`` for C2) to tag answers with
     - Many techniques leave nothing on the wire. ATT&CK's data components
       `Network Traffic Content <https://attack.mitre.org/datacomponents/DC0085/>`_ and
       `Network Traffic Flow <https://attack.mitre.org/datacomponents/DC0078/>`_ say which ones a
       capture can detect; the rest are *not observable*
   * - Diamond Model
     - One intrusion event as adversary, capability, infrastructure, victim
     - The entity axis: every host gets a role
     - Benign roles (DC, proxy, NAT) and decoys (honeypot, sinkhole) have no corner
   * - Cyber Kill Chain
     - Seven stages in order
     - The order of the story: delivery, then install, then C2
     - Too coarse to drive checks; lateral movement and credential access are absent
   * - `MITRE D3FEND <https://d3fend.mitre.org/>`_
     - Defensive techniques
     - Names for decoy techniques (decoy network resource, decoy session)
     - Describes defences, not what a capture shows

The Diamond Model
~~~~~~~~~~~~~~~~~

The Diamond Model of Intrusion Analysis (Caltagirone, Pendergast and Betz, 2013) describes one
intrusion event by four connected corners:

.. code-block:: text

               Adversary
              /         \
    Capability --------- Infrastructure
              \         /
                Victim

- **Adversary** — who is behind it (a named group, or "unknown operator").
- **Capability** — what they used: the malware, an exploit, a stolen credential.
- **Infrastructure** — what they used it through: C2 servers, domains, IPs, a download URL.
- **Victim** — who or what was hit: a host, a user, an organisation.

Knowing one corner lets an analyst *pivot* to the others: from a C2 IP (infrastructure) to every
host that talked to it (more victims); from a malware family (capability) to its known C2 domains.

TracePcap already fills three corners from a capture. ``victim`` and ``signed-in-user`` are the
victim; ``malware`` and ``downloads`` the capability; ``c2`` and ``remote-access`` the
infrastructure. The adversary is almost never visible in traffic, so it is a *not observable* cell.
The model's corners don't fit every host, which is why the entity axis adds roles of its own.

The model
---------

.. code-block:: text

   Capture context          Entities: what hosts are       Activities: ATT&CK tactics
   ---------------          ------------------------       --------------------------
   vantage point            workstation, server, DC        Reconnaissance ... Impact
   completeness             proxy, NAT, scanner            (14 tactics)
   time span                C2, remote-access server
                            honeypot  (new)
          |                            |                              |
          +----------------------------+------------------------------+
                                       |
             each standard question declares its category and the evidence it needs
                                       |
          +-------------+--------------+--------------+------------------+
          |             |                             |                  |
       Answered     Ruled out                       Open          Not observable (new)

- **Capture context** frames every answer: where the capture was taken (inside the LAN, on the
  internet uplink, on a honeypot sensor), whether it is complete (the IDS *capture completeness* note, #1274), and
  how long it spans.
- **Entities** are roles a host can hold, adjudicated from evidence like any other identity (see
  :doc:`adjudication-explainability`).
- **Activities** are the ATT&CK tactics. Questions stay small deterministic checks; what changes is
  that each declares its place here.

The four statuses
~~~~~~~~~~~~~~~~~

================  ==============================================================================
Status            Meaning
================  ==============================================================================
Answered          A standard question concluded something for this category.
Ruled out         Candidates were tested and rejected (the ``Considered`` records, #1298).
Open              Nothing was concluded, and the capture could show it. A category no check covers
                  yet is Open too, marked *no check yet*, so a gap in TracePcap never reads as a
                  gap in the capture.
Not observable    The capture can't show it: the category never shows in traffic (Adversary,
                  Resource Development), it mostly happens on a host and no check concluded it
                  anyway (Persistence, Privilege Escalation), or none of the traffic its checks
                  read is in the capture (no SMB or DCE-RPC means lateral movement can't be
                  judged). **New.**
================  ==============================================================================

Each category carries how much of it a capture can show (*wire*, *partly*, *rarely*, *never*), and
each check declares the traffic it reads. The status follows from those two and the capture:

1. A check concluded something: **Answered**. Its candidates were all rejected: **Ruled out**.
2. Otherwise, a *never* category, or a *rarely* one: **Not observable**.
3. Otherwise, if the category's checks read traffic and none of it is in the capture: **Not
   observable**.
4. Otherwise: **Open** (with *no check yet* when no check covers it).

Coverage today
--------------

Of the 14 ATT&CK tactics, today's questions cover 6. Five more are uncovered but show on the wire,
fully or in part: Reconnaissance, Defense Evasion and Discovery, and partly Collection and Impact.

.. list-table::
   :header-rows: 1
   :widths: 22 26 18 34

   * - Category
     - Today's question
     - Visible in a pcap?
     - Gap to fill
   * - **Entities**
     -
     -
     -
   * - Victim
     - ``victim``
     - Yes
     -
   * - Who's signed in
     - ``signed-in-user``
     - Yes
     -
   * - C2 server
     - ``c2``
     - Yes
     -
   * - Remote-access server
     - ``remote-access``
     - Yes
     -
   * - Scanner
     - none
     - Yes
     - Hosts sweeping ports or addresses
   * - Honeypot
     - none
     - Yes
     - See `Honeypots`_
   * - Adversary
     - none
     - No
     - Not observable
   * - **Activities (ATT&CK)**
     -
     -
     -
   * - Reconnaissance
     - none
     - Yes
     - Port scans, sweeps, brute-force sources
   * - Resource Development
     - none
     - No
     - Mark not observable
   * - Initial Access
     - ``downloads``
     - Yes
     - Exploit attempts from IDS alerts
   * - Execution
     - ``downloads`` (partly)
     - Partly
     - Script-engine fetches
   * - Persistence
     - none
     - Rarely
     - Not observable, unless a scheduled task is seen over RPC
   * - Privilege Escalation
     - none
     - Rarely
     - Mark not observable
   * - Defense Evasion
     - none
     - Yes
     - DNS tunnelling, DGA lookups, domain fronting
   * - Credential Access
     - ``kerberos-attack``
     - Yes
     - NTLM relay, cleartext passwords
   * - Discovery
     - none
     - Yes
     - LDAP and SMB enumeration, AD queries
   * - Lateral Movement
     - ``lateral-movement``
     - Yes, internal captures only
     -
   * - Collection
     - none
     - Partly
     - Shares bulk-read before exfiltration
   * - Command and Control
     - ``c2``, ``malware``, ``remote-access``
     - Yes
     -
   * - Exfiltration
     - ``data-transfer``
     - Yes
     -
   * - Impact
     - none
     - Partly
     - Ransomware SMB rewrite patterns
   * - **Capture context**
     -
     -
     -
   * - Completeness
     - none (the IDS completeness note, #1274, shows it today)
     - Yes
     - Phase 3
   * - Vantage point
     - none
     - Yes
     - Internal, uplink, or honeypot sensor
   * - Time span
     - none
     - Yes
     - Phase 3

Honeypots
---------

Honeypots are common and mostly left at their default settings, which makes them easy to spot. One
scan of 2.9 billion IPv4 addresses found 21,855 honeypots, most still on default configuration
(Srinivasa, Pedersen and Vasilomanolakis, 2021). That research probes hosts actively. TracePcap only
sees recorded traffic, so it can use a signal only when the capture contains the exchange that
reveals it.

Signals a capture can show
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 20 32 16 32

   * - Signal
     - Example
     - Honeypots
     - Seen passively?
   * - Default service banner
     - SSH ``SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2`` (Cowrie), ``SSH-2.0-OpenSSH_5.1p1 Debian-5``
       (Kippo)
     - Cowrie, Kippo
     - Yes, on any SSH connection
   * - Stale HTTP ``Server`` header
     - ``BaseHTTP/0.3 Python/2.5.1``, ``Apache/1.3.29``
     - Glastopf, Amun
     - Yes, on any HTTP reply
   * - Default TLS certificate
     - Issuer and subject the same across every install
     - Dionaea
     - Yes, from Suricata's TLS records (#1240)
   * - Static default web page
     - The same page body as the stock install
     - Glastopf, Dionaea, Conpot
     - Yes, from the HTTP file hash
   * - Handshake deviation
     - ``protocol mismatch`` reply to a malformed SSH banner
     - Kippo, Cowrie
     - Only if an attacker's scanner sent that probe
   * - OS mismatch
     - A Linux TTL and TCP options behind a "Windows" SMB server
     - Dionaea
     - Yes, from the SYN-ACK
   * - Every login accepted
     - Logins succeed after failures, or with any password
     - Cowrie
     - Yes, for Telnet and FTP; SSH is encrypted
   * - Fan-in with no fan-out
     - Many internet sources connect in; the host starts nothing except attacker-named downloads
     - Any
     - Yes, from conversations

Banner strings change between honeypot versions, so they belong in a bundled signature file that can
be updated offline, not in code.

A honeypot conclusion is graded ``INFERRED`` and needs **at least two independent signals**: a
default banner alone could be a real, old server. That matches the multi-stage rule the research
uses to avoid false positives.

How a honeypot changes other answers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. A decoy marked as **victim** isn't an incident: the answer says "decoy, expected", not
   "infected".
2. The **scanners and brute-forcers** reaching it become the subjects worth reporting.
3. **Downloads** to a honeypot are the catch, not an infection: their hashes and URLs are reported as
   attacker tooling.
4. A capture **taken on a honeypot sensor** makes every inbound attack expected. That is capture
   context, so the whole summary is framed as a sensor log.

Code changes
------------

1. ``StandardQuestion`` **gains two methods**, both with defaults so existing questions keep
   compiling:

   - ``categories()`` — the categories it answers. One check can answer several: ``c2`` answers
     both *C2 server* and *Command and Control*.
   - ``requires()`` — the traffic it reads, as tshark protocol and nDPI application names, each
     with what it shows for that check (lateral movement: SMB, DCE-RPC, RDP).

2. **A category catalogue** in the backend lists every category, including those with no question
   yet, and is served through the API. It replaces the question groups the frontend keeps in
   ``features/insights/protocolInsights.ts``.
3. **Coverage per capture** adds the *Not observable* status, computed from each category's
   visibility, its checks' ``requires()`` and the protocols present (see `The four statuses`_).
4. **The Investigation Summary and Story** frame their answers by the capture context, and Story
   leads with a summary instead of the four fixed question cards (see `Story layout`_).
5. **Honeypot detection** is a host role in identity adjudication (#499), fed by a contributor that
   reads banners, certificates and HTTP bodies against the bundled signature file.

Story layout
------------

Story opens with **a summary, not a grid** (chosen over a full grid, an ATT&CK chain and a
Diamond-first layout):

1. **One sentence and one bar** say where the investigation stands, framed by the capture context:
   "Nothing is concluded yet. 12 categories have evidence to look at, 4 were ruled out, and 5 can't
   be seen in this capture." The bar splits all categories by status.
2. **Worth a look next** lists only the *open* categories whose evidence is in the capture, each with
   what to check and a link to it.
3. **Ruled out** and **Not observable** fold away, each category with its reason ("no SMB or DCE-RPC
   between internal hosts; a capture inside the LAN would answer it").
4. **Show all** opens the full grid of every category and its status.
5. **The narrative** sits beside it as a timeline, each step tagged with its ATT&CK tactic, and the
   Q&A below suggests questions about the gaps ("What would show lateral movement?").

Answered categories lead the summary when there are any, each opening its *How we got here*.

Delivery plan
-------------

Four phases, each its own PR into ``dev``:

1. **Catalogue and tagging** *(done)*. ``categories()`` and ``requires()`` on every question, the
   ``Category`` enum and ``CategoryCatalogue`` in the knowledge layer, and
   ``GET /investigation-categories``. ``CategoryCatalogueTest`` pins the mapping to
   `Coverage today`_.
2. **Coverage on the Overview and Story.** *Worth a look* shows every category with its four-way
   status, from the API, and Story takes the summary-first layout above. Gate: on the four
   malware-traffic-analysis.net walkthrough captures, every status is right by hand check.
3. **Capture context.** Infer the vantage point (internal, uplink, sensor) from address mix and
   direction, and frame the summary by it. Gate: a public honeypot capture reads as a sensor log.
4. **Honeypot role.** Signature file, contributor, adjudicated role graded ``INFERRED`` from two or
   more signals. Gate: a true positive on a Cowrie or Dionaea capture, and no false positive on the
   walkthrough captures.

After that, each uncovered category (Reconnaissance, Defense Evasion, Discovery, Collection,
Impact) is one PR.

Open questions
~~~~~~~~~~~~~~

- Tag with ATT&CK tactic ids only, or technique ids too (``T1021.002`` for SMB admin shares)?
  Techniques are more precise but need upkeep each ATT&CK release.
- Which honeypot captures can we test with? Our own Cowrie and Dionaea in a lab, or public sensor
  captures.
- Should *Not observable* say what evidence would have answered it ("capture inside the LAN to see
  lateral movement")?
- Does the vantage point need a user override, as host roles have?

References
----------

- Caltagirone, Pendergast, Betz. *The Diamond Model of Intrusion Analysis*. 2013.
- Srinivasa, Pedersen, Vasilomanolakis.
  `Gotta Catch 'em All: A Multistage Framework for Honeypot Fingerprinting
  <https://arxiv.org/abs/2109.10652>`_. 2021.
- Vetterl, Clayton.
  `Bitter Harvest: Systematically Fingerprinting Low- and Medium-interaction Honeypots at Internet
  Scale <https://www.cl.cam.ac.uk/~amv42/papers/vetterl-clayton-bitter-harvest-woot-18.pdf>`_.
  USENIX WOOT 2018.
- MITRE. `ATT&CK <https://attack.mitre.org/>`_ and `D3FEND <https://d3fend.mitre.org/>`_.
