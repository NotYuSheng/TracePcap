Windows Sign-in Identity
========================

Most of what TracePcap tells you about a host answers *"what is this?"* — a device
type, a manufacturer, a set of service roles. On a Windows/Active Directory network,
two protocols also routinely name the human behind a workstation — Kerberos
authentication and LDAP directory lookups. TracePcap reads that name automatically
wherever it is present, with no configuration required, and uses it two ways:

- as **evidence that the host is a domain-joined Windows workstation**, contributing
  to its device-type classification (a host signing in to Active Directory is a
  laptop/desktop, not a router or a printer); and
- as the host's **signed-in user** attribute — a person-level fact recorded on the
  host alongside its passively-discovered hostname.

.. note::

   This is **fully deterministic**. The username is read from specific protocol
   fields and weighted by how directly each one proves who is signed in. There is
   **no LLM, no machine learning, and no guessing** — every contribution traces back
   to a named packet field.

.. important::

   Not every host has a signed-in user. Routers, IoT devices, external servers, and
   any host that never appears in Kerberos or LDAP traffic simply have none — a
   normal, expected empty state, not a failure.


How it works
------------

TracePcap reads two signals from the capture, each with a different evidentiary
weight, during the same analysis pass that classifies device types:

1. **Kerberos AS-REQ** — the initial authentication request a Windows client sends
   when a user logs in names the account requesting a ticket. Because the client
   sends this about *itself*, it is treated as strong, direct evidence of who is
   signed in at that IP. It contributes a strong vote toward the ``LAPTOP_DESKTOP``
   device type.

2. **LDAP directory lookup** — a client asking Active Directory to resolve a display
   name (for example, Explorer or the shell looking up the current user's full name)
   carries that name in the query itself. This is weaker evidence: the query is
   usually about the asking host's own identity, but the wire protocol gives no
   guarantee — a helpdesk or admin tool could just as easily be looking up *someone
   else's* account. It contributes a smaller vote.

The **signed-in user** attribute records the strongest available claim: a
Kerberos-authenticated principal outranks an LDAP lookup name. Both, when present,
appear as separate lines in the host's classification evidence, so an analyst sees
each protocol's contribution and why their weights differ, rather than a single
opaque number.

Two exclusions apply unconditionally:

- **Machine accounts** (principals ending in ``$``, e.g. ``DESKTOP-ABC123$``) are
  never surfaced — they name the computer object, not a person.
- **Cleartext LDAP bind credentials** are never read or stored. Older-style LDAP
  binds can carry a password in the clear on the wire; TracePcap's parser does not
  request or inspect that field, by design, regardless of whether one is present in
  a given capture.

The domain controller is never mislabelled with an account. Only the client-sent
Kerberos AS-REQ is read for attribution; the KDC's replies (which also carry account
names, but are sent *by* the DC) are deliberately ignored, so the DC's own IP is
never tagged with every account it ever issued a ticket for.


Worked example — a real incident capture
-----------------------------------------

Analysing a real malware-traffic-analysis.net exercise (a Windows workstation
compromised by the STRRAT remote-access trojan), TracePcap resolved the victim's
identity from the capture with no manual filtering required:

.. code-block:: text

   Kerberos AS-REQ    172.16.1.66 -> 172.16.1.4   CNameString = ccollier
   LDAP searchRequest 172.16.1.66 -> 172.16.1.4   baseObject  = CN=Clark Collier,CN=Users,DC=...

Both signals name the same person. On the host ``172.16.1.66`` the classification
evidence reads:

.. code-block:: text

   LAPTOP_DESKTOP (160)
     TTL 128 (Windows range)                                → +30
     Windows domain sign-in as "ccollier" (Kerberos AS-REQ) → +40
     Directory lookup of "Clark Collier" (LDAP)             → +15
     MAC OUI matched "Intel Corporate"                      → +40
     ...

and the host carries ``ccollier`` as its **signed-in user** (source: Kerberos). The
domain controller ``172.16.1.4`` — which the KDC replies pass through — is correctly
left with no signed-in user.

Filtering LDAP lookups down to *which attributes were requested* (display name,
surname, and so on) was tried and rejected during development: a directory lookup for
a certificate template legitimately requests the same kind of attributes as a lookup
for a person, and would otherwise be misread as a human identity. The reliable signal
turned out to be the shape of the directory entry itself — person accounts live in a
distinct part of the directory (``CN=Users``) that infrastructure objects do not.


Where it surfaces in the UI
----------------------------

Open any host's detail panel (from the Network Diagram, Analysis Overview, Compare,
Monitor drift panels, or Conversation Detail — they all share the same entity view):

- The **Signed-in user** row appears in the host's details alongside its **Hostname**,
  with a small badge showing whether the name came from Kerberos (stronger) or LDAP
  (weaker).
- The sign-in shows up in the host's **Evidence weighed → Identity** breakdown as one
  or two lines naming the principal and the protocol that observed it — the same
  explainability trail behind every device-type verdict.


What it is *not*
-----------------

- It is **not** a separate adjudicated verdict with its own override. The signed-in
  user is an observed attribute of the host and a contributor to its device-type
  classification — not a standalone "who is this?" question competing with "what is
  this?".
- It is **not** a general user-activity or authentication log. It resolves one thing —
  *whose account is associated with this host* — from the two specific signals above,
  not a full record of every login or lookup observed.
- It does **not** decrypt or need to decrypt anything. Kerberos and LDAP both carry
  these identity fields in the clear (or via mechanisms TracePcap already parses); no
  keys or credentials are required or used.
