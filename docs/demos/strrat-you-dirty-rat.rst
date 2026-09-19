STRRAT infection — "You dirty rat!"
====================================

This walkthrough runs a real, publicly available network-forensics incident through TracePcap's
*existing* features, end to end, to show what the tool surfaces on its own — no CTF-specific tuning,
no prior knowledge of the network, working from the capture alone.

The scenario is malware-traffic-analysis.net's `2024-07-30 "You dirty rat!" exercise
<https://www.malware-traffic-analysis.net/2024/07/30/index.html>`_ — a STRRAT remote-access-trojan
infection on a simulated Active-Directory-joined corporate LAN. Every finding below was produced by
TracePcap on first upload and cross-checked against the exercise's own official answer key.

.. note::

   Nearly everything here comes from TracePcap's **deterministic** layers — Suricata, nDPI, the host
   classifier, and the Kerberos/LDAP identity extractor. The LLM "Story mode" narrative is shown last,
   as a layer *on top* of those findings, not the source of them. That distinction is the point of the
   demo: the ground truth is deterministic and reproducible.


Getting the capture
-------------------

The pcap and its answer key are **not committed to this repository** — third-party incident archives
can carry live malware samples, so they stay out of git by policy. Download them from the source
instead:

- Page: https://www.malware-traffic-analysis.net/2024/07/30/index.html
- The capture ZIP is password-protected. malware-traffic-analysis.net uses a fixed scheme:
  ``infected_YYYYMMDD`` where the date is the post date — so this one is ``infected_20240730``.
  (The scheme is stated in the site's ``about`` image, deliberately not machine-readable.)

For this exercise the STRRAT loader arrived as an out-of-band email attachment, so the pcap itself
contains only the post-infection network traffic — which is exactly what TracePcap works from.

Upload the ``.pcap`` through the normal :doc:`upload flow </features/pcap-upload>`. Everything below is
available once analysis completes.


The victim host, named without asking
-------------------------------------

Open host ``172.16.1.66`` in the network diagram. Working only from the packets, TracePcap has already
built its profile:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Attribute
     - Value (all derived from the capture)
   * - Device type
     - ``LAPTOP_DESKTOP`` (100% — a clear winner)
   * - MAC / manufacturer
     - ``00:1e:64:ec:f3:08`` → Intel Corporate
   * - Hostname
     - ``DESKTOP-SKBR25F.local`` (via mDNS)
   * - **Signed-in user**
     - **ccollier** (via Kerberos)
   * - Observed TTL
     - 128 (Windows range)
   * - Share of capture
     - 97.1% of all bytes — the top talker by far

The **signed-in user** is the newest piece (see :doc:`/features/windows-identity`). The exercise's
answer key recovers the victim's identity by hand, filtering LDAP for a ``givenName`` attribute.
TracePcap now does this automatically: it reads the client's own **Kerberos AS-REQ**
(``kerberos.CNameString = ccollier``) and the **LDAP directory lookup** of that account
(``CN=Clark Collier,CN=Users,DC=…``) and reports the person behind the keyboard. Both show up in the
host's *Evidence weighed* breakdown, contributing to the laptop/desktop verdict:

.. code-block:: text

   LAPTOP_DESKTOP
     TTL 128 (Windows range)                                → +30
     Windows domain sign-in as "ccollier" (Kerberos AS-REQ) → +40
     Directory lookup of "Clark Collier" (LDAP)             → +15
     MAC OUI matched "Intel Corporate"                      → +40
     Mostly-outbound with varied apps                       → +10
     Desktop app "Teams"                                    → +20

The domain controller (``172.16.1.4``) is *not* credited with a signed-in user, even though the
Kerberos and LDAP replies pass through it — only the client-sent AS-REQ is used for attribution, and
machine-account principals (``DESKTOP-SKBR25F$``) are excluded, so no computer object is ever mistaken
for a person.


The malware and its command-and-control
---------------------------------------

TracePcap ships Suricata with the Emerging Threats ruleset, run automatically on upload. The STRRAT
family is named directly — no manual pcap digging:

.. code-block:: text

   172.16.1.66:49754  →  141.98.10.79:12132   (TCP)
   Suricata: "ET MALWARE STRRAT CnC Checkin"  (sid 2030358, severity 1)
   411 packets, ~39 KB, 10:40:05 → 10:48:34

So the capture alone yields the family (**STRRAT**), the **C2 endpoint** (``141.98.10.79:12132``), and
the infected host (``172.16.1.66``, i.e. ccollier's workstation) unprompted.

.. tip::

   A small cross-check worth noting: the exercise's published answer key lists the C2 as
   ``141.98.10.69``, while the destination in the capture — and the address the ET STRRAT rule matches —
   is ``141.98.10.79``. A one-digit transcription difference; TracePcap reports what is on the wire.


Behaviour, even where nDPI can't name it
----------------------------------------

Beyond the signature hit, TracePcap's behavioural analysis flags the shape of the traffic:

- **A textbook beacon.** A CRITICAL periodic-connection finding fires on ``172.16.1.66 → 172.16.1.4:139``
  (SMB/NetBIOS): five flows, ~30,023 ms average interval, coefficient of variation **0.000** — zero
  jitter, a machine keeping time, not a human.
- **Top-talker + fan-out.** ``172.16.1.66`` initiated 368 flows to 46 distinct destinations and produced
  97.1% of all bytes in the capture.
- **A visibility gap, stated honestly.** 66.9% of conversations (285 of 426) could not be classified by
  nDPI — TracePcap surfaces this as a HIGH finding rather than pretending to full coverage, which is
  exactly the context an analyst needs.

None of this required the malware to be decrypted or the loader to be present; it falls out of the
metrics.


Story mode: a narrative layer, and its limits
----------------------------------------------

With a local LLM configured (see :doc:`/configuration/llm-setup`), Story mode writes a SOC-style
narrative from the analysis. On this capture it produces a well-grounded, multi-section report — it
even runs its own follow-up investigation queries to confirm each hypothesis against the data:

  *"Four CRITICAL beacon findings identify highly periodic connections from 172.16.1.66 to
  172.16.1.4:139 … an average interval of 30,023 ms, and CV=0.000 … consistent with command-and-control
  keepalive, persistence, or a scheduled beacon mechanism."*

It correctly centres the investigation on ``172.16.1.66``, the SMB beacon, the 9.3 MB TLS burst, and the
directory-service access — all traced back to specific conversations.

.. important::

   But the narrative, working from traffic *metrics*, never named the actual STRRAT C2
   (``141.98.10.79``) or the victim ``ccollier`` — those came only from the deterministic layers
   (the Suricata signature and the Kerberos/LDAP extractor). This is the demo's closing point: the
   LLM is a helpful narrator, not the detector. Treat its story as a readable summary of the
   deterministic findings, and always anchor conclusions in the signature hits and extracted facts it
   sits on top of.


What this demonstrates
----------------------

From one upload of a real incident capture, with no prior knowledge of the network, TracePcap
surfaced automatically:

- **Who** — ``ccollier`` (Clark Collier), the signed-in user, from Kerberos/LDAP.
- **What** — a STRRAT infection, named by Suricata.
- **Where** — C2 at ``141.98.10.79:12132``, and the victim workstation ``172.16.1.66``.
- **How it behaves** — a zero-jitter 30-second beacon, top-talker dominance, and an honest visibility gap.

The most forensically valuable answers came from deterministic analysis, reproducibly, offline. The
LLM narrative is a convenience on top — and, as shown, one whose conclusions must be checked against
the deterministic evidence beneath it.
