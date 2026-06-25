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

Suricata is gated **independently of nDPI** — it has its own per-file toggle, so
you can run one without the other.

Enabling Suricata
-----------------

Suricata detection is selected **per file** at upload time:

- In the **upload analysis-options modal**, tick **"Suricata IDS threat
  detection"**. (The analysis-options modal is shown when
  ``VITE_ANALYSIS_OPTIONS=true`` — see :doc:`../configuration/environment-variables`.)
- The same toggle applies when merging PCAPs.

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
- The ruleset version is recorded in the image (``/opt/suricata-ruleset-version``).
  To refresh the rules, rebuild the backend image.
