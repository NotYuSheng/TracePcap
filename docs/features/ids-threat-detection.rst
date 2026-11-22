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
- **Conversation detail** — the full list of alert signatures for that
  conversation.
- **Security alert count** — Suricata matches contribute to the per-conversation
  security-alert total alongside nDPI risk flags.
- **CSV export** — the ``suricataAlerts`` column is included in conversation CSV
  exports.

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
the number of rules, and ``importError`` if an imported bundle wasn't used.

Using a newer ruleset offline
-----------------------------

To update the rules without rebuilding the image (the usual case for an
air-gapped install):

1. On any machine with internet, download ET Open's
   ``emerging.rules.tar.gz`` from https://rules.emergingthreats.net/open/suricata/.
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
