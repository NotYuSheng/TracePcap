Windows Identity Resolution
===========================

Most of what TracePcap tells you about a host answers *"what is this?"* — a device
type, a manufacturer, a set of service roles. **Windows Identity** answers a
different question: *"who is logged into this?"*. On a Windows/Active Directory
network, two protocols routinely name the human behind a workstation — Kerberos
authentication and LDAP directory lookups — and TracePcap resolves that name
automatically wherever it is present, with no configuration required.

.. note::

   Windows Identity is **fully deterministic**. It is a fixed priority rule over
   two observed wire signals, weighted by how directly each one proves who is
   logged in. There is **no LLM, no machine learning, and no guessing** — every
   claim traces back to a specific protocol field.

.. important::

   Not every host has a Windows identity. Routers, IoT devices, external servers,
   and any host that never appears in Kerberos or LDAP traffic simply have none —
   this is a normal, expected empty state, not a failure.


How it works
------------

TracePcap reads two signals from the capture, each with a different evidentiary
weight:

1. **Kerberos AS-REQ** — the initial authentication request a Windows client
   sends when a user logs in names the account requesting a ticket. Because the
   client sends this about *itself*, it is treated as strong, direct evidence:
   whoever is logged in at that IP.

2. **LDAP directory lookup** — a client asking Active Directory to resolve a
   display name (for example, Explorer or the shell looking up the current
   user's full name) carries that name in the query itself. This is weaker
   evidence: the query is usually about the asking host's own identity, but the
   wire protocol gives no guarantee of that — a helpdesk or admin tool could just
   as easily be looking up *someone else's* account from that IP.

When both signals are present for one host, the Kerberos claim wins as the
primary answer, and the LDAP claim rides along as corroborating context rather
than being averaged against it or discarded. When only one signal is present,
that claim stands on its own, at a correspondingly lower confidence for LDAP-only
claims. If a host is seen authenticating as more than one distinct person — a
shared kiosk, for instance — the identity is marked **contested** rather than
silently picking one.

Two exclusions apply unconditionally:

- **Machine accounts** (principals ending in ``$``, e.g. ``DESKTOP-ABC123$``)
  are never surfaced as a Windows identity — they name the computer object, not
  a person.
- **Cleartext LDAP bind credentials** are never read or stored. Older-style LDAP
  binds can carry a password in the clear on the wire; TracePcap's parser does
  not request or inspect that field, by design, regardless of whether one is
  present in a given capture.


Worked example — a real incident capture
-----------------------------------------

Analysing a real malware-traffic-analysis.net exercise (a Windows workstation
compromised by the STRRAT remote-access trojan), TracePcap resolved the
victim's identity from the capture with no manual filtering required:

.. code-block:: text

   Kerberos AS-REQ   172.16.1.66 -> 172.16.1.4   CNameString = ccollier
   LDAP searchRequest 172.16.1.66 -> 172.16.1.4  baseObject  = CN=Clark Collier,CN=Users,DC=...

Both signals name the same person. The adjudicated result:

.. code-block:: json

   {
     "ip": "172.16.1.66",
     "primaryLabel": "ccollier",
     "basis": "MACHINE",
     "confidence": 90,
     "contested": false,
     "candidates": [
       { "label": "ccollier", "source": "kerberos_as_req", "score": 90 },
       { "label": "Clark Collier", "source": "ldap_dn", "score": 55 }
     ]
   }

The Kerberos-authenticated username became the primary label; the LDAP display
name is preserved as a candidate so an analyst can see both pieces of evidence,
not just the winner.

Filtering LDAP lookups down to *which attributes were requested* (display name,
surname, and so on) was tried and rejected during development: a directory
lookup for a certificate template legitimately requests the same kind of
attributes as a lookup for a person, and would otherwise be misread as a human
identity. The reliable signal turned out to be the shape of the directory
entry itself — person accounts live in a distinct part of the directory that
infrastructure objects do not.


Where it surfaces in the UI
----------------------------

Open any host's detail panel (from the Network Diagram, Analysis Overview,
Compare, Monitor drift panels, or Conversation Detail — they all share the same
entity view) and, directly below the existing **Identity** panel, a **Windows
Identity** panel appears whenever a Kerberos or LDAP claim exists for that host.
It shows the resolved name, a confidence score, and a **Why** breakdown listing
every contributing signal — the same explainability pattern used throughout
TracePcap's adjudicated conclusions.

Like every adjudicated answer in TracePcap, it can be corrected: **"I
disagree"** lets an analyst override it outright, and the override is recorded
with who made it and when. A human override always wins over what the traffic
shows.


What it is *not*
-----------------

- It is **not** a general user-activity or authentication log. It resolves one
  thing — *whose account is associated with this host* — from the two specific
  signals above, not a full record of every login or lookup observed.
- It does **not** decrypt or need to decrypt anything. Kerberos and LDAP both
  carry these identity fields in the clear (or via mechanisms TracePcap already
  parses); no keys or credentials are required or used.
- It does **not** rank a Windows identity against a host's device type or role.
  "Who is logged in" and "what kind of device is this" are answered
  independently — a workstation's identity says nothing about whether it is
  correctly classified as a laptop, and vice versa.
