Investigation Framework
=======================

.. note::

   **Status: built.** All four phases are in: the categories and their catalogue (phase 1), each
   category's status per capture (phase 2), the capture context (phase 3) and the honeypot role
   (phase 4). ``GET /api/v1/investigation-categories`` serves the catalogue; the investigation
   report carries every category's status, the capture's context and the hosts that read as
   honeypots; the Overview and Story show them. The uncovered tactics are next. See `Delivery
   plan`_.

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

1. A check concluded something: **Answered**. Every check covering it tested candidates and rejected
   them all: **Ruled out**. One check ruling out its candidate (a TeamViewer peer) leaves a category
   its other checks also cover (Command and Control) open.
2. Otherwise, a *never* category, or a *rarely* one: **Not observable**.
3. Otherwise, if the category's checks read traffic, none of it is in the capture, and no other
   traffic worth a look for it is either: **Not observable**. NTLM with no Kerberos keeps Credential
   Access open, with NTLM to look at.
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
     - the honeypot role
     - Yes
     - Built: see `Honeypots`_
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
     - ``CaptureContextService``, from the capture-quality notes (#1268)
     - Yes
     - Complete, complete with notes, or partial
   * - Vantage point
     - ``CaptureContextService``, from the address mix
     - Yes
     - Inside the LAN, uplink, one host, exposed server, or sensor; analyst can override
   * - Time span
     - ``CaptureContextService``, from the capture summary
     - Yes
     - Duration, first and last packet

Capture context
---------------

``CaptureContextService`` answers the three context categories for every capture, with no LLM, and
the investigation report carries them as ``context``. Story opens with them in one line:
*On a honeypot or sensor (192.168.100.28) · inferred · complete · 24 h*.

**Vantage point** is a vote over the address mix, which comes from two database aggregates: the
conversations per pair of hosts, with which side opened them, and the ports the busiest host answered
on. Internal means a private address or one of the operator's private ranges.

.. list-table::
   :header-rows: 1
   :widths: 22 50 10

   * - Vantage
     - Shape
     - Score
   * - On a honeypot or sensor
     - One host in at least 80% of conversations. Others opened most of them, at least 5 hosts on at
       least 5 of its ports.
     - 75
   * - On an exposed server
     - The same, but fewer openers or ports.
     - 65
   * - On one host
     - One host in at least 80% of conversations, and it opened most of them. A host that also takes
       a sensor's probes keeps *sensor* as runner-up (50): a compromised honeypot attacking out.
     - 70
   * - Inside the LAN
     - At least 2 internal hosts, and at least 20% of conversations between them.
     - 70
   * - On the internet uplink
     - At least 2 internal hosts, under 20% between them, and at least 60% between an internal and
       an external host.
     - 65

Under 10 conversations, or a mix none of these fit, leaves it undetermined, and the reason says why
(for a capture with no internal addresses, to add the operator's private ranges). So does a capture
of one pair of hosts, both in most conversations and the busiest with under 3 peers: it could have
been taken at either end. The top two within 15 points is *contested*.

It is the ``vantage-point`` question about entity ``capture`` at the generic adjudication endpoints
(:doc:`adjudication-explainability`). Analyst evidence adds its weight to a candidate, and an
override replaces the vote. Evidence on a vantage the address mix left undetermined settles it as
the analyst's answer, not an inference. Story's *Why · change* opens the vote, its reasons, the override and the
evidence. A vantage of the uplink makes Lateral Movement *not observable* when the capture has no
traffic for it and no conversations between internal hosts, since those don't cross an uplink.

**Time span** is the first and last packet, in the server's time zone like the app's other times.

**Completeness** is the capture-quality notes as a verdict: *partial* when traffic is missing or
uninspected (gaps, the IDS out of memory or unable to read it), *complete, with notes* for the rest.
Sessions longer than the IDS's inspection depth are listed but don't qualify it: they say how far
Suricata read, not what the capture holds.

Checked against real captures: day 1 of the Honeynet Project's Scan of the Month 28 reads as a sensor,
with 18 outside hosts opening 44 conversations on 18 ports. Day 3, the same honeypot compromised and
flooding out, reads as one host, with sensor as runner-up. The 2010 forensic challenge 1 attack trace
(5 conversations) is undetermined. The four malware-traffic-analysis.net captures read as one host's
traffic, and a merged capture of many networks reads as inside the LAN.

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

What's built
~~~~~~~~~~~~

**Extract.** ``ServiceBannerExtractor`` runs one tshark pass and records what each server said about
itself (table ``service_banners``): its SSH banner and HASSH, FTP greeting, HTTP ``Server`` header,
SMB native OS and server name, MySQL version, and the initial TTL of its SYN-ACKs (32, 64, 128 or
255, rounded up from the one seen). Only the server side counts: the address and port that sent the
SYN-ACK. When the capture began mid-connection, fields only a server sends (HASSH, FTP greeting,
HTTP ``Server``, SMB server name, MySQL version) count unless the sender is known to be the client,
and the SSH version string and SMB native OS, which both sides send, are taken from the lower
port. Ports 2222 and 2223 are decoded as
SSH and Telnet, since Cowrie is often exposed there and tshark 3.6 only knows SSH on 22. TLS
certificates come from the conversations' own TLS fields.

**Signatures.** ``backend/src/main/resources/honeypot/signatures.json`` lists each fingerprint with
the honeypot it names, the field it matches (``equals`` or ``contains``), a strength and why. Every
value in it was checked against the honeypot's own image or source, or comes from the cited research:

=============================  ==========  ===================================================================
Signature                      Strength    Why
=============================  ==========  ===================================================================
Dionaea TLS certificate        strong      ``O=dionaea.carnivore.it, CN=Nepenthes Development Team``: only Dionaea
Dionaea SMB server name        strong      ``HOMEUSER-3AF6FE`` (``dionaea/smb/extras.py``)
Cowrie HASSH                   medium      Cowrie's key exchange (Twisted Conch); no OpenSSH release offers it
Glastopf HTTP ``Server``       medium      ``BaseHTTP/0.3 Python/2.5.1``
Cowrie, Kippo SSH banners      weak        ``OpenSSH_9.2p1 Debian-2+deb12u3`` and older: real Debian sends them
Dionaea FTP, MySQL, SMB OS     weak        "DiskStation FTP server ready.", 5.7.16, Windows 5.1: real products' too
Amun HTTP ``Server``           weak        ``Apache/1.3.29``
=============================  ==========  ===================================================================

**Behaviour.** Read only for hosts a signature or an analyst already points at, the strongest 50
first: *fan-in* (5 or more hosts opened conversations to it, and it opened at most 10% of its own;
weak), *many services* (it answered on 5 or more ports; medium), and *OS mismatch* (its SMB says
Windows but its packets start at TTL 64; weak, since Samba on Linux does this too).

**The vote.** Strong signals are worth 45 points, medium 30, weak 15. A host reads as a honeypot
when it has **two or more signals, at least one a signature, worth 60 points together**. The
honeypot named is the one its signatures' points favour. Below that, a host with two or more
signals is listed with why it falls short ("its signals add up to 30 points of the 60 a honeypot
needs"); a host with one signature match and nothing else is only counted, since an internet scan
can meet hundreds of servers still sending an old honeypot's banner.

**Override and evidence.** Each host's role is an adjudicated question (``honeypot``, entity key
the host's address) at the generic adjudication endpoints. An override (*Honeypot*, *Not a
honeypot*, or a label of your own) wins outright and keeps the signals for reference; evidence adds
its weight to *Honeypot* or *Not a honeypot*, and counts as a signal, so an analyst's word plus one
signature can settle a host. Evidence worth 60 points settles a host on its own: the two-signal rule
guards against a real server's stock banner, and an analyst's word isn't one. An override on any
address, signals or not, answers it. The host details drawer reads one host's role
(``GET /files/{fileId}/honeypots/{ip}``), with no signal too, so any host can be marked there.

**Where it shows.** The Honeypot category is *Answered* when a host reads as one, *Open* when a host
has two or more signals but not enough, and *Ruled out* when every server's banners and
certificates were checked and none showed enough ("no server matched a honeypot signature (7
servers checked)"). Only servers that sent a banner or certificate count as checked; with none, it
stays *Open*. When the capture context reads the capture as taken on a honeypot or sensor, no
signature match leaves it *Open* too: a high-interaction honeypot or a bare sensor sends nothing a
signature knows. Story's summary names each honeypot under the capture context, and *Why ·
change* opens its signals, the vote, an override and evidence.

**The gate capture.** No public pcap of a modern Cowrie or Dionaea exists: honeypot datasets
publish the honeypots' logs (MURHCAD, sweetie-data), not packets. ``scripts/honeypot-capture.sh``
makes one anyone can rebuild: the official ``cowrie/cowrie`` and ``dinotools/dionaea`` images,
pinned by digest, on an internal Docker network in the documentation range, probed by six attacker
containers (SSH and Telnet logins, an FTP login, HTTP and TLS, SMB, MS-SQL, a port sweep and a
version scan). The only change from the honeypots' defaults is turning on Cowrie's Telnet.

How a honeypot changes other answers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. A decoy marked as **victim** isn't an incident: the answer says "decoy, expected", not
   "infected".
2. The **scanners and brute-forcers** reaching it become the subjects worth reporting.
3. **Downloads** to a honeypot are the catch, not an infection: their hashes and URLs are reported as
   attacker tooling.
4. A capture **taken on a honeypot sensor** makes every inbound attack expected. That is capture
   context, so the whole summary is framed as a sensor log.

How it's built (#1330): ``HoneypotContributor`` posts each honeypot (inferred, or set by an
analyst) to the board as a ``honeypot`` finding, and each host that opened conversations to one as
a ``honeypot-contact`` finding. A decoy's own conversations out, and decoys probing each other,
don't count. The questions read them:

- ``VictimQuestion`` leaves honeypots out. ``HoneypotActivityQuestion`` answers a decoy that talked
  to a known C2 instead: "198.51.100.22, a Cowrie honeypot, contacted the known C2 …: the attack it
  was set up to record, not an infection". The C2 is still answered as one.
- ``DownloadsQuestion`` says a decoy *caught* a file: "…, a Dionaea honeypot, caught x.exe (…) from
  …: attacker tooling, not an infection. SHA-256 …".
- ``HoneypotActivityQuestion`` (``honeypot-activity``, the *Scanner* category) names the hosts that
  reached a decoy, those that reached the same decoys as one answer: "7 hosts (198.51.100.101, …)
  reached the Cowrie honeypot 198.51.100.22 and the Dionaea honeypot 198.51.100.45 (242
  conversations): a decoy has no real users, so this is scanning or an attack".

Marking a host *Not a honeypot* takes it off the board, and every answer reads as before.

Code changes
------------

1. ``StandardQuestion`` **gains two methods**, both with defaults so existing questions keep
   compiling:

   - ``categories()`` — the categories it answers. One check can answer several: ``c2`` answers
     both *C2 server* and *Command and Control*.
   - ``requires()`` — the traffic it reads, as tshark protocol and nDPI application names, each
     with what it shows for that check (lateral movement: SMB, DCE-RPC, RDP).

2. **A category catalogue** in the backend lists every category, including those with no question
   yet, and is served through the API. It replaced the question groups the frontend kept in
   ``features/insights/protocolInsights.ts`` (removed in phase 2).
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
2. **Coverage on the Overview and Story** *(done)*. ``CategoryCoverage`` computes each category's
   status on a capture and ``CategoryLeads`` where to look for it. Both come with the investigation
   report (``categories``). *Worth a look* reads them, and Story takes the summary-first layout
   above (items 1 to 4; the tactic-tagged timeline waits on the narrative). Gate: on the four
   malware-traffic-analysis.net walkthrough captures, every status is right by hand check.
3. **Capture context** *(done)*. ``CaptureContextService`` infers the vantage point from the address
   mix and answers completeness and time span, and Story's summary opens with them (see `Capture
   context`_). The vantage point can be overridden and given evidence. Gate: Scan of the Month 28
   day 1, a public honeynet capture, reads as a sensor.
4. **Honeypot role** *(done)*. ``ServiceBannerExtractor`` records what servers say about
   themselves, ``HoneypotRoleService`` reads them against the bundled signature file with the
   hosts' behaviour, and each host's role is graded ``INFERRED`` from two or more signals, with an
   override and evidence (see `What's built`_). Gate: on the scripted capture, Dionaea reads as
   Dionaea (95: both strong signatures, three weak, fan-in, 14 ports, OS mismatch) and Cowrie as
   Cowrie (60: HASSH, banner, fan-in). No false positive: no signature matched on the nine
   malware-traffic-analysis.net exercises in ``eval/pcaps`` or the Ultimate PCAP. PANDAcap's 64
   sessions (Zenodo 3759652, a high-interaction SSH honeypot: a real Ubuntu with genuine OpenSSH)
   are ruled out, as they should be, since nothing it sends is a honeypot's; the only matches there
   are single old Cowrie and Kippo banners on servers its compromised VM scanned, which are counted,
   not concluded.

After that, each uncovered category (Reconnaissance, Defense Evasion, Discovery, Collection,
Impact) is one PR.

Open questions
~~~~~~~~~~~~~~

- Tag with ATT&CK tactic ids only, or technique ids too (``T1021.002`` for SMB admin shares)?
  Techniques are more precise but need upkeep each ATT&CK release.
- High-interaction honeypots (PANDAcap, a real system) can't be told from a real server by what
  they send. Their tell is behaviour over time, such as every login accepted, which needs
  cleartext Telnet or FTP logins to count.
- Should *Not observable* say what evidence would have answered it everywhere, as Lateral Movement
  does from the uplink?

Decided: a honeypot changes the answers it touches (see `How a honeypot changes other answers`_,
#1330). Anything inferred gets an override and analyst evidence, as host roles have. The vantage
point and the honeypot role have both. Test captures for phase 4: no public pcap exists, so the gate
uses a scripted capture of the official images (``scripts/honeypot-capture.sh``).

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
