IDS Threat Detection (Suricata)
===============================

TracePcap integrates **Suricata** as an offline, signature-based intrusion
detection engine. It runs as a **Stage 3 enrichment** pass alongside nDPI and
tshark, surfacing rule-based threat alerts next to each conversation so that
known-bad traffic patterns are flagged automatically.

Unlike a live IDS sensor, Suricata here runs in **offline pcap-read mode**
(``suricata -r``) over each uploaded capture — there is no live interface
tap and no network egress. The **Emerging Threats Open** ruleset is bundled
into the backend Docker image at build time, so detection works fully offline
with no runtime rule downloads.

The image ships **Suricata 8.0** from OISF's ``suricata-8.0`` Ubuntu PPA (Ubuntu
22.04's own package is 6.0.4, an end-of-life line), with the ET Open ruleset
published for that engine version. Captures are fed to a long-running engine
over its Unix socket, so the ruleset is built once rather than per capture;
compiled rule groups are cached in ``/opt/suricata-cache`` so a restarted engine
starts faster. That engine runs with ``security.limit-noproc`` off: Suricata 7+
otherwise sets its own process limit to zero once started, and in socket mode
that stops it starting a worker for each capture.

Suricata also inspects TCP streams that were **already open when the capture
began** (``stream.midstream``). By default it skips any stream whose handshake it
didn't see, which suits a live sensor but not a capture, which is a slice of
time: a short excerpt of a PsExec session otherwise produces no alerts at all.
Measured on 71 captures (the eval exercises, four holdouts, 36 clean samples and
26 labelled attack captures from PCAP-ATTACK), it added alerts on six attack
captures (PsExec, smbexec, Zerologon, DNS-over-TCP SIGRed, and NTLM sign-ins in
two more) and changed no answer on any capture. It applies to captures analysed from now on:
re-analyse an earlier one to pick it up.

It also inspects packets **whatever their checksum** (``pcap-file.checksum-checks`` and
``stream.checksum-validation`` off, as ``-k none`` does). A capture taken on one of the hosts holds
the checksums its network card would have filled in later (offload), so every packet that host sent
looks corrupt. Suricata's default notices that statistically, too late on a short capture, and
until then it drops those packets from stream and protocol inspection: half of each conversation.
Measured on the same 71 captures: alerts on four more (PCAP-ATTACK's Foudre C2, which now gets its C2
and victim answers, NTLM sign-ins in SpoolSample and PsLoggedOn, and a WhatsApp capture), and no
other answer changed. One
loss: Zerologon's exploit rule no longer fires on PCAP-ATTACK's capture of it, which has no TCP
handshakes. Suricata orients those connections server-first, so the rule's "to server" condition
never matches; it only fired before because the server's packets were being dropped (#1277).
The trade-off: a packet that really was corrupted, or a decoy sent with a bad checksum on purpose
to confuse an IDS (which the real endpoint would drop), is inspected too. In a capture taken off the
wire the offload case is far more common, so inspecting everything is the default here.

How it works
------------

1. After packet parsing and nDPI classification, Suricata reads the PCAP and
   evaluates it against the bundled ruleset.
2. Alert events from Suricata's ``eve.json`` output are parsed and mapped onto
   the conversations they belong to.
3. Matching alert signatures are stored on each conversation and counted into a
   security-alert total shown across the UI.
4. The same ``eve.json`` has a ``tls`` record for each TLS session. Its facts fill
   in what nDPI didn't provide: the client **JA3** fingerprint (nDPI 6 reports
   JA4 instead), the server JA3S, SNI, certificate subject, issuer and validity,
   and the negotiated **TLS version**, which nothing else records. They only
   fill gaps; a value nDPI found is never replaced. Suricata's ``http``,
   ``dns`` and ``fileinfo`` records aren't read, because tshark already extracts
   the same information (the web server log, the DNS query log and file
   extraction).

On the STRRAT incident capture (184 TLS conversations) this took client JA3 from
0 to 153, hostnames from 65 to 162 and certificate subjects from 25 to 60, with
no measurable change in analysis time.

5. The ``tls`` record also carries the **server certificate itself** (the image
   turns on Suricata's ``certificate`` and ``chain`` TLS fields). TracePcap parses
   it offline with the JDK and records, per conversation: the certificate's
   alternative names, key type and size, signature algorithm, how many
   certificates the server sent, and whether it is **self-signed** (issuer equals
   subject *and* it verifies with its own key, rather than comparing names). Three
   checks follow, shown as badges in the conversation's TLS section and counted in
   the AI story's TLS summary:

   - **Weak key**: RSA or DSA under 2048 bits, EC under 256.
   - **SHA-1/MD5 signature**: forgeable signature algorithms.
   - **Doesn't cover the server name**: none of the certificate's names, wildcards
     included (one label only), matches the name the client asked for (SNI). A
     misconfiguration, interception, or a server pretending to be something it
     isn't.

   This describes the certificate; it is not a trust verdict. There is no trust
   store and no revocation check offline. TLS 1.3 encrypts the certificate, so for
   those sessions none of this is available (on the 2024-07-30 training capture,
   25 of 56 TLS sessions carried one). Captures analysed before this show nothing
   until re-analysed.

Suricata is gated **independently of nDPI** — it has its own per-file toggle, so
you can run one without the other.

Enabling Suricata
-----------------

Suricata detection is selected **per file** at upload time:

- On the home page, under **Analyse with**, tick **Intrusion alerts
  (Suricata)** before choosing the file. It is **off by default** because it
  adds significant processing time.
- The same toggle applies when merging PCAPs.

A deployment-wide kill-switch, ``SURICATA_ENABLED`` (default ``true``), can
disable Suricata for **every** upload regardless of the per-file choice — set
it to ``false`` to skip IDS analysis across the board. See
:doc:`../configuration/environment-variables`.

.. note::
   Suricata adds meaningful processing time to analysis. Leave it off for quick
   triage and enable it when you specifically want signature-based threat
   detection on a capture.

Viewing IDS Alerts
------------------

IDS Alerts appear wherever conversations are shown:

- **Conversation list** — a purple **IDS Alerts** column shows the matched
  signatures as badges (long labels are truncated with a tooltip).
- **Conversation detail** — each alert as it fired: when, on which side, the
  rule's rating and confidence, and the HTTP request it fired on (see
  :doc:`conversations`).
- **Security alert count** — Suricata matches contribute to the per-conversation
  security-alert total alongside nDPI risk flags.
- **CSV export** — the ``suricataAlerts`` column is included in conversation CSV
  exports.

Capture completeness
~~~~~~~~~~~~~~~~~~~~

No alert is only reassuring if Suricata saw the traffic. The Overview's
**Needs a look** card adds a *Capture completeness* note whenever something
limits that, using Suricata's own counters for the run and TracePcap's
conversations (also at ``GET /api/v1/files/{fileId}/capture-quality``):

- **Suricata couldn't read the capture** (warning): it read far fewer packets
  than the file holds. A pcapng that mixes link types (several interfaces in one
  file) does this: Suricata reads nothing and reports success. See issue #1273.
- **Gaps in TCP streams** (warning): packets are missing from the capture, so
  alerts and files in those streams can be missed.
- **Suricata ran out of memory** (warning): some traffic wasn't inspected.
- **Connections already open when the capture began** (over 10% of TCP): how
  they started, and which side opened them, isn't in the capture.
- **Undecodable packets**: truncated or malformed.
- **Sessions past Suricata's inspection depth**: it inspects the first 1 MiB of
  each TCP stream, so an alert later in a longer session can be missed.

Nothing is shown when none of these apply.

Protocol anomalies
~~~~~~~~~~~~~~~~~~

Suricata also reports *anomalies*: traffic a protocol parser found malformed or
one-sided (``APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION``, say). They aren't
attacks, so they don't count as alerts. The conversation detail lists them,
collapsed, under **Protocol anomalies**, in plain words with Suricata's name
beside each.

Filtering by IDS Alert
~~~~~~~~~~~~~~~~~~~~~~~

The conversation **filter panel** has a searchable **IDS Alerts** facet. Pick
one or more alert signatures to show only conversations that matched them. The
available values are populated from the distinct alerts present in the current
file, so the list reflects what was actually detected.

Offline Operation
-----------------

Suricata fits the project's offline requirement (see
:doc:`../getting-started/offline-deployment`):

- The Suricata binary and the Emerging Threats Open ruleset are baked into the
  backend image at build time.
- No rules are fetched at runtime and no telemetry leaves the host.
- The ruleset's date is shown in the app (see below); to use newer rules without
  rebuilding, import them from a folder.

The ruleset's age
-----------------

Signatures go stale: a ruleset frozen when the image was built keeps matching
yesterday's threats, and a capture with **no** alerts may only mean the rules are
old. So the ruleset in use, and how old it is, is shown next to Suricata's results:
on a capture's Overview (*Needs a look*), on a conversation with Suricata alerts,
in a monitored network's security tab, and on **Settings › System**. Once it's
older than ``SURICATA_RULESET_STALE_DAYS`` (default 30) it's flagged.

The same information is at ``GET /api/v1/system/suricata``: the engine version,
``source`` (``built-in`` or ``imported``), the ruleset's date and age, ``stale``,
the number of rules in the ruleset, ``loadedRuleCount`` / ``failedRuleCount``
(what the engine reported loading on its last start), and ``importError`` if an
imported bundle wasn't used. A ``loadedRuleCount`` of 0 means Suricata can't see
the ruleset, so no capture gets IDS alerts; the app logs an error and the note
beside the alerts says so, since a capture without alerts would otherwise look
clean.

Using a newer ruleset offline
-----------------------------

To update the rules without rebuilding the image (the usual case for an
air-gapped install):

1. On any machine with internet, download ET Open's
   ``emerging.rules.tar.gz`` for the engine's version, e.g.
   https://rules.emergingthreats.net/open/suricata-8.0.8/ for Suricata 8.0.8 (the
   version is on ``GET /api/v1/system/suricata``). The unversioned
   ``open/suricata/`` path is an older, 5.0-era ruleset.
   One or more ``.rules`` files work too, with ``classification.config`` and
   ``reference.config`` alongside if you have them.
2. Copy it into the ``suricata-rules/`` folder next to ``docker-compose.yml``
   (or the folder ``SURICATA_RULES_DIR`` names). It's mounted read-only into the
   backend.
3. Within about two minutes the app shows the new ruleset: TracePcap checks the
   folder every minute, and test-loads the bundle with ``suricata -T`` (about a
   minute) before using it. Analyses waiting meanwhile just wait for it.

A bundle that won't load (corrupt, truncated, or with no valid rules) is reported
in the app, with Suricata's reason, and the rules **built into the image** are
used, so Suricata is never left without rules. Empty the folder to go back to
the built-in rules.

An imported tarball is dated by the newest file in it (ET's publication time);
loose ``.rules`` files by the newest rule's ``updated_at``. Nothing is ever
downloaded by TracePcap itself.

.. note::

   ET Open is redistributable, which is why the image can ship it. Snort's
   Registered and Subscriber rules are not, so they can't be baked into the
   image, but you can import them yourself the same way, subject to their licence.
