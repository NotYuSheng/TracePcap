Network Monitor
===============

The Network Monitor enables black-box network characterisation from a series of
PCAP captures — no prior knowledge of the network is required. You feed in one
or more PCAPs, and the tool builds an inventory, maps topology, and tracks how
the network changes over time, starting entirely from observed traffic.

Rather than analysing a single file in isolation, you group related PCAPs into
a **Network**, add them as **Snapshots**, and let the engine compare consecutive
snapshots to surface behavioural changes as prioritised **Change Events**.

This is different from a traditional blue-team SIEM or IDS. There is no
persistent sensor, no pre-existing asset inventory, and no assumed knowledge of
the network under review. The Monitor is designed for situations where you are
*producing* that documentation — audits, assessments, incident investigations,
or repeated capture sessions on an unfamiliar network.

Overview
--------

- Group any number of PCAP files into a named network.
- Snapshots are automatically ordered by capture start time — you can add them
  in any order.
- Each time a snapshot is added, the engine compares it against its chronological
  predecessor and emits change events.
- Events are shown in a filterable feed with severity badges, mark-as-reviewed
  workflow, and free-text notes.
- Drift panels show which devices, protocols, applications, and IP addresses are
  active, absent, or newly appeared across snapshots.
- A network diagram overlays change highlights on the topology graph for each
  snapshot, accessible by clicking any row in the Capture Timeline.
- Subnets can be defined or auto-detected to group IP addresses in the IP
  Addresses drift panel.
- Devices and IP addresses can be annotated with **role labels** (manually or
  via AI suggestion) to provide operational context.
- **External Events** log real-world events (maintenance windows, firmware
  upgrades) with timestamps for correlation against network changes.
- **Analyst Annotations** record free-text notes that feed into AI insight
  generation.
- **Network Insights** generates a structured AI narrative across all snapshots,
  correlating change events with roles, external events, and analyst notes.

Getting Started
---------------

1. Navigate to **Monitor** in the top navigation bar.
2. Click **Create Network** and give it a name and optional description.
3. Open the network card to enter the detail view.
4. Click **Manage PCAPs** to open the PCAP management modal, then **Add PCAP**
   and select a file that has already been analysed (status: *Completed*).
   Repeat for each capture. The same modal lets you **remove** a snapshot from
   the network later.
5. Change events appear automatically once two or more snapshots exist.

.. note::
   Only files with status **COMPLETED** can be added as snapshots. Upload and
   analyse the file first via the standard PCAP upload flow.

Change Detection Signals
------------------------

The engine runs four independent detection passes when comparing two consecutive
snapshots:

Signal 1 — Device (MAC) Drift
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tracks which hardware devices (identified by MAC address) appear or disappear.

- **MAC_ADDED** (WARNING) — a MAC address present in the new snapshot was not
  seen in the previous one. Payload includes IP, manufacturer, and device type.
- Devices that disappear are shown as **absent entities** in the Devices drift
  panel (greyed-out, strikethrough) rather than as change events, since a host
  going offline is expected behaviour.

Signal 2 — IP ↔ MAC Binding Drift
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Detects changes in the IP-to-MAC mapping, which can indicate DHCP activity or
ARP cache poisoning:

- **IP_MAC_DRIFT / WARNING** — the same MAC address now holds a different IP
  address (DHCP reassignment).
- **IP_MAC_DRIFT / CRITICAL** — the same IP address is now claimed by a
  different MAC address (potential ARP spoofing). This signal is emitted
  independently of the DHCP warning so that a device simultaneously changing
  its own IP and spoofing another cannot suppress the critical alert.

Signal 3 — ISP / ASN / Gateway Change
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Monitors external connectivity by tracking public IP addresses and their
associated autonomous systems:

- **ASN_CHANGE** (INFO) — a new Autonomous System appears in the external
  traffic (new CDN, cloud provider, or peering partner).
- **GATEWAY_CHANGE** (CRITICAL) — the top-traffic external IP (used as a
  gateway heuristic) changes between snapshots. This can indicate ISP failover,
  a routing change, or a man-in-the-middle scenario.

Private addresses (RFC 1918: ``10.0.0.0/8``, ``172.16.0.0/12``,
``192.168.0.0/16``), loopback, and link-local addresses are excluded from
external IP analysis.

Signal 4 — Protocol / Application / VPN Drift
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tracks which protocols, nDPI application names, and VPN risk fingerprints
appear or disappear:

- **PROTOCOL_ADDED** (INFO) — a network protocol not seen before appears.
- **APP_ADDED** (INFO or WARNING) — a new application appears; VPN-related
  app names are elevated to WARNING.
- **VPN_DRIFT / CRITICAL** — a VPN risk fingerprint (e.g. ``VPN Protocol``)
  appears in the new snapshot.
- **VPN_DRIFT / WARNING** — a VPN risk fingerprint that was present is no
  longer seen (device stopped using a VPN).

Removed protocols and applications are surfaced as absent entities in the drift
panels rather than as events.

Severity Levels
---------------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Severity
     - Meaning / examples
   * - **CRITICAL**
     - Requires immediate attention. Examples: IP claimed by a different MAC
       (possible ARP spoof), gateway IP changed, VPN fingerprint newly appeared.
   * - **WARNING**
     - Notable change worth investigating. Examples: new device on the network,
       MAC address obtained a different IP, VPN fingerprint disappeared, VPN
       app detected.
   * - **INFO**
     - Informational. Examples: new ASN or cloud provider seen, new protocol or
       application appeared.

The network card on the Monitor list page shows **Unreviewed Critical** and
**Unreviewed Warnings** counts so resolved events do not inflate the numbers.

Change Event Feed
-----------------

The event feed on the network detail page lists all change events in reverse
chronological order. Each event shows:

- Severity badge (CRITICAL / WARNING / INFO)
- Change type and a human-readable description
- From / to snapshot labels
- Detected-at timestamp
- Reviewed checkbox and free-text notes field

Filtering
~~~~~~~~~

The feed can be filtered by:

- **Severity** — CRITICAL, WARNING, INFO, or ALL
- **Change type** — MAC_ADDED, IP_MAC_DRIFT, ASN_CHANGE, GATEWAY_CHANGE,
  PROTOCOL_ADDED, APP_ADDED, VPN_DRIFT
- **Reviewed status** — Unreviewed (default), Reviewed, or All

The badge count in the filter bar reflects the current filter selection.

Marking as Reviewed
~~~~~~~~~~~~~~~~~~~

Click the checkbox on any event to mark it as reviewed. Add a note to record
the reason (e.g. "Known DHCP lease renewal — expected"). The network card
unreviewed counts update immediately.

Capture Timeline
----------------

The Capture Timeline table lists all snapshots in order. A mode toggle in the
header switches between two views:

- **By PCAP** (default) — one row per snapshot.
- **By Time** — snapshots are bucketed into a selectable interval
  (``1m`` / ``5m`` / ``30m`` / ``1h`` / ``1d`` / ``1mo``), aggregating captures,
  packets, and change counts per bucket. The ``1mo`` interval buckets by
  calendar month. Each bucket row expands to list the individual PCAPs within
  the interval, and each PCAP still opens its snapshot detail modal. The By Time
  view is computed entirely client-side from existing snapshot data — no
  re-analysis is triggered.

The Changes indicator is rendered as the same badge pill in all three places
(By PCAP rows, the By Time bucket aggregate, and the nested per-PCAP rows);
clickable badges show a pointer cursor.

Clicking any snapshot row opens the **Snapshot Detail** modal, which contains
five tabs:

- **Network Diagram** — topology graph for that snapshot with change highlights
  overlaid. Navigate between snapshots with the prev/next arrows or dropdown;
  use ← → arrow keys as a shortcut.
- **Changes** — all change events that were produced when this snapshot was
  compared to its predecessor.
- **Context & Notes** — free-text fields for capturing what was happening during
  this capture (sent to the AI when generating insights).
- **Subnets** — per-snapshot subnet overrides (see `Per-Snapshot Subnet Overrides`_).
- **Insights** — AI-generated analysis scoped to this single snapshot (see
  `Network Insights`_ below).

The Changes column on the timeline row shows a badge with the count and highest
severity. Click the badge directly to jump straight to the Changes tab.

Drift Panels
------------

Three drift panels on the network detail page give a cross-snapshot summary.
All three panels have a **search box** at the top to filter by name.

Devices Panel
~~~~~~~~~~~~~

Shows all MAC addresses seen across all snapshots. Each device badge is
colour-coded (deterministic hue per MAC). Click a badge to open the **Device
History Modal**, which shows:

- Role label and AI suggestion controls (see `Node Role Annotation`_)
- Latest manufacturer, device type, TTL, and confidence score with classification
  signal breakdown
- **Snapshot History** table — IP address, device type, protocols, and
  applications per snapshot (paginated; use ← → arrow keys to page)
- **Notes** tab — free-text notes persisted globally for this device

Absent devices (not seen in the latest snapshot) appear greyed-out with
strikethrough.

Protocols & Applications Panel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Shows all protocols and nDPI application names seen across all snapshots.
Absent entries are greyed-out with strikethrough. Click any badge to open the
**Entity Detail** modal showing stats for that protocol or application in the
latest snapshot, and its capture history across all uploaded files.

IP Addresses Panel
~~~~~~~~~~~~~~~~~~

Shows all IP addresses observed in conversation endpoints across all snapshots.
When subnet definitions exist (see `Subnet Definitions`_), IPs are grouped by
matching CIDR with the subnet label as a header; unmatched IPs fall into an
"Unmatched" group. Without subnet definitions, IPs are split into **Private**
and **Public**.

Click any IP badge to open the **Entity Detail** modal, which shows:

- Role label and AI suggestion controls
- Device classification (manufacturer, device type, TTL, confidence) from the
  latest snapshot
- **Snapshot History** table — MAC address (with "changed" badge if it changed
  between snapshots), manufacturer, device type, protocols, and applications per
  snapshot
- **Notes** tab

Absent addresses follow the same greyed-out / strikethrough pattern.

Private IP Overrides
~~~~~~~~~~~~~~~~~~~~

By default, TracePcap classifies addresses according to RFC 1918
(``10.0.0.0/8``, ``172.16.0.0/12``, ``192.168.0.0/16``) and RFC 6598
(``100.64.0.0/10``). Some networks use public IP address space internally
(e.g. a terminal that is assigned a routable address but is physically
on a private LAN). Private IP Overrides let you reclassify any public IP
or CIDR range as internal so that change-detection and IP grouping treat
it correctly.

**How to add an override:**

1. Open the network detail page and scroll to the **IP Addresses** drift panel.
2. Expand the **Private IP Overrides** section at the bottom of the panel.
3. Enter an IP address (e.g. ``203.0.113.42``) or a CIDR range
   (e.g. ``203.0.113.0/24``). A bare IP is stored as a ``/32`` (or ``/128``
   for IPv6).
4. Optionally enter a label (e.g. ``Branch Office Router``).
5. Click **Add override**.

Overrides take effect immediately. Matching IPs move from the **Public**
group into the **Private** group (or into the appropriate subnet group if
subnet definitions are also configured). They are also excluded from
ASN/gateway change analysis — so a gateway change involving an overridden
IP will not generate a ``GATEWAY_CHANGE`` or ``ASN_CHANGE`` event.

Overrides are global across all networks. To remove one, click the trash
icon next to it in the list.

.. note::

   Overrides affect IP *classification* only. Traffic to and from overridden
   addresses is still captured, analysed, and displayed normally.

Baseline Definitions
--------------------

Baseline Definitions let you declare *expected* entities so that their presence
does not generate change events. Defined entries are checked during change
detection and suppressed if they match.

Supported definition types:

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Type
     - What it suppresses
   * - ``DEVICE``
     - A known MAC address (e.g. a permanent workstation)
   * - ``IP_MAC_BINDING``
     - A known IP-to-MAC pair (e.g. a statically assigned server)
   * - ``GATEWAY``
     - A known gateway IP
   * - ``PROTOCOL``
     - A protocol name that is always expected
   * - ``APP``
     - An application name that is always expected
   * - ``VPN_FINGERPRINT``
     - A VPN risk string that is intentional (e.g. a corporate VPN)

To add a baseline entry, click **Add Baseline** in the Baseline Definitions
panel and fill in the type, entity key, optional value, and notes.

Subnet Definitions
------------------

Subnet Definitions let you declare the CIDR structure of the network under
review. Because the Monitor works from traffic alone, subnets are either
inferred automatically or entered manually.

**Scan All Snapshots** — runs detection across every snapshot in the network
and scores candidates by **consistency** (how many snapshots the subnet appears
in). Results include a density score (observed hosts ÷ subnet capacity) and a
consistency badge (e.g. "3/4 snapshots"). Single-snapshot candidates are flagged
in amber.

**Detect from snapshot** — select one snapshot and click **Detect** to infer
candidates from that capture alone.

**Add manually** — enter any CIDR (e.g. ``10.14.0.0/16``) with an optional
label (e.g. ``OT Floor — Level 2``) and description.

Detection algorithm
~~~~~~~~~~~~~~~~~~~

The scanner collects all private IP addresses (RFC 1918) seen in host
classifications for the selected snapshot(s). For each IP, candidate CIDRs at
every prefix length from /20 to /29 are scored by host density. A greedy
non-overlapping selection picks the highest-density candidates, preferring
tighter prefixes.

**Limitations:**

- Prefix range /20–/29 only — very large blocks (/8–/19) and point-to-point
  links (/30–/32) are outside the search range.
- No routing topology awareness — the algorithm has no knowledge of VLANs or
  gateway assignments.
- Segments with fewer than 3 classified hosts will not appear.
- Only hosts that generated enough traffic to be fingerprinted are counted.
- Private IPs in VPN overlays are treated the same as LAN hosts.

Saved subnets are global across all networks and can be edited or deleted at any
time. Each saved subnet row has a **diagram** button to open the Subnet Diagram
modal, which filters the topology graph to show only nodes within that CIDR.

Per-Snapshot Subnet Overrides
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Individual snapshots can carry their own subnet list that **shadows** the global
definitions for that snapshot's change detection and IP grouping. Snapshots
without overrides fall back to the global config unchanged.

To set overrides for a snapshot:

1. Open the snapshot via the Capture Timeline.
2. Go to the **Subnets** tab.
3. If no overrides exist, click **Customize for this snapshot** — the current
   global definitions are pre-populated as *Inherited* rows.
4. Add, edit, or remove rows. Inherited rows carry a grey *Inherited* badge;
   rows you add carry no badge.
5. Click **Save subnet overrides**.

To revert a snapshot to global definitions, click **Reset to global** — this
clears all overrides for that snapshot.

Overrides can also be set at upload time: in the **Add PCAP Snapshot** dialog,
expand the **Subnet Overrides (optional)** section before clicking upload.

**When to use per-snapshot overrides:**

- A capture was taken on a network segment with a different CIDR structure than
  the rest of the dataset.
- During incident investigation you want to scope subnet labels to the specific
  segments involved (e.g. ``10.0.3.0/24 — Floor 3 OT Devices``) without
  changing the global definitions used by every other snapshot.
- A one-off capture contains traffic from a third-party network that should not
  influence the global subnet inventory.

Node Role Annotation
--------------------

Any IP address or MAC device can be annotated with a **role label** — a short
human-readable name describing what the entity is (e.g. "Water Pump PLC",
"SCADA Historian", "Edge Router").

To assign a role, click any IP or device badge to open its detail modal, then
use the **Role** section at the top of the Details tab:

- **Edit** — type a label and optional description and save.
- **Suggest with AI** — the LLM analyses the device's traffic signals
  (manufacturer, device type, observed applications, protocols) and suggests a
  label. The suggestion is shown with an "AI suggested" badge.
- **Accept** — keeps the AI suggestion; the label is saved as a
  **Manual label** (an analyst-assigned label).
- **Discard** — removes the unconfirmed suggestion.

A label saved by an analyst (typed directly or by accepting a suggestion) carries
a **Manual label** badge. This records *what the host is* — its identity. It is
not a guarantee about future behaviour: the Monitor continues to detect and flag
deviating activity from a labelled host. Keep time-bounded behavioural
observations in **Entity Notes** rather than in the label itself.

Role labels are global (not per-network) — assigning a role to an IP or device
once makes it available wherever that entity appears, including in AI-generated
insights.

Entity Notes
~~~~~~~~~~~~

The **Notes** tab in any Entity Detail modal lets you write free-text notes
about a device, IP address, protocol, or application. Notes persist globally and
are included in the context sent to the LLM when generating Network Insights.

External Events
---------------

The **External Events** panel records real-world events alongside the network
timeline — maintenance windows, firmware upgrades, shift changes, or any other
operational context that could explain observed network changes.

Each event has:

- **Event time** — when the real-world event occurred (not when it was logged)
- **Title** — short description
- **Description** — optional longer explanation

External events are sent to the LLM as part of the insight generation prompt,
enabling it to correlate network changes with known operational activity (e.g.
"New MAC appeared at 14:02 — a firmware upgrade was logged at 13:55").

Analyst Annotations
-------------------

The **Analyst Annotations** panel stores free-text notes about the network as a
whole. Unlike snapshot context (which is scoped to one capture) or entity notes
(scoped to one device/IP), annotations are global to the network and persist
across insight generations.

The 10 most recent annotations are included in every Network Insights prompt
under a "Prior Analyst Annotations" section, giving the LLM continuity across
sessions.

Network Insights
----------------

The **Network Insights** panel generates an AI-authored structured analysis of
the entire network timeline. It synthesises change events, device roles, external
events, snapshot context/notes, entity notes, and analyst annotations into a
narrative report.

Generation options
~~~~~~~~~~~~~~~~~~

Click the **gear icon** to expand the options panel before generating:

**Audience** — controls vocabulary and framing:

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Option
     - Description
   * - *Technical* (default)
     - MACs, IPs, protocol names verbatim. For active investigators.
   * - *Executive*
     - Plain English, business impact language, no jargon. For management briefings.
   * - *OT / ICS*
     - Framed around operational and industrial impact — PLCs, HMIs, Purdue model zones.

**Focus** — controls what the LLM emphasises:

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Option
     - Description
   * - *Security* (default)
     - Suspicious patterns, ARP spoofing indicators, lateral movement leads.
   * - *Operational*
     - Expected vs unexpected changes from a network operations perspective.
   * - *Compliance*
     - Deviations from baseline definitions; reviewed vs unreviewed events.

The audience and focus used to generate an insight are shown as badges in the
footer of the result so you always know the context.

Output sections
~~~~~~~~~~~~~~~

A completed insight contains:

- **Summary** — 2–4 sentence overview of the period
- **Narrative sections** — detailed analysis broken into titled sections
- **Anomalies** — flagged deviations with LOW / MEDIUM / HIGH severity
- **Correlations** — links between specific external events and specific network
  changes, with an explanation
- **Recommendations** — suggested follow-up actions

.. tip::
   For richer, more contextual insights:

   1. Assign role labels to key devices and IP addresses first.
   2. Log external events with accurate timestamps before generating.
   3. Add analyst annotations with any context the LLM may not be able to infer
      (e.g. "This network is an OT environment — 192.168.10.x is the OT segment").
   4. Write snapshot context notes for any capture taken during a known event.

Per-snapshot insights
~~~~~~~~~~~~~~~~~~~~~

Each snapshot also has its own **Insights** tab (inside the Snapshot Detail
modal). This generates an insight scoped to that single snapshot — what changed
versus its predecessor, whether the changes are explained by external events in
the capture window, and what is recommended. The same audience and focus options
are available.

Network Diagram Overlay
-----------------------

The **Network Diagram** tab inside the Snapshot Detail modal renders the
topology graph for the selected snapshot. Change events are overlaid as coloured
highlights:

- Red nodes — CRITICAL events
- Yellow/orange nodes — WARNING events
- Green nodes — INFO events

Use the snapshot selector or ← → arrow keys to step through the timeline. Nodes
involved in change events are labelled with the event type (e.g. "Potential ARP
spoof", "New device"). Click a highlighted node to open its details.

Polling / Auto-Refresh
----------------------

Both the Monitor list page and the network detail page support auto-refresh:

- A **last updated** timestamp shows when data was last fetched.
- A **refresh** button triggers an immediate reload.
- An **interval dropdown** lets you choose the polling frequency:

  - 10 seconds
  - 30 seconds
  - 1 minute
  - 5 minutes
  - Manual (no polling)

The polling runs in the browser — no server-side push is involved.

REST API Reference
------------------

All monitor endpoints are prefixed with ``/api/v1/monitor``.

Networks
~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 35 55

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/monitor/networks``
     - List all networks.
   * - ``GET``
     - ``/api/v1/monitor/networks/{networkId}``
     - Get a single network by ID.
   * - ``POST``
     - ``/api/v1/monitor/networks``
     - Create a network. Body: ``{ "name": "string", "description": "string" }``.
   * - ``DELETE``
     - ``/api/v1/monitor/networks/{networkId}``
     - Delete a network and all its snapshots and events.

Snapshots
~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 55 35

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/monitor/networks/{networkId}/snapshots``
     - List snapshots ordered by capture time.
   * - ``POST``
     - ``/api/v1/monitor/networks/{networkId}/snapshots``
     - Add a snapshot. Body: ``{ "fileId": "uuid", "subnetOverrides": [...]? }``. ``subnetOverrides`` is optional; omit or pass ``null`` to use global definitions. Triggers change detection automatically.
   * - ``PATCH``
     - ``/api/v1/monitor/networks/{networkId}/snapshots/{snapshotId}``
     - Update snapshot context, notes, or subnet overrides. Body: ``{ "context": "string?", "notes": "string?", "subnetOverrides": [{ "cidr": "string", "label": "string?", "description": "string?", "inherited": boolean }]? }``. ``subnetOverrides: null`` leaves overrides unchanged; ``[]`` clears all (reverts to global); a non-empty list replaces the existing overrides.
   * - ``DELETE``
     - ``/api/v1/monitor/networks/{networkId}/snapshots/{snapshotId}``
     - Remove a snapshot and re-run change detection for affected pairs.

Change Events
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 55 35

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/monitor/networks/{networkId}/changes``
     - List change events. Optional query params: ``changeType``, ``severity``.
   * - ``PATCH``
     - ``/api/v1/monitor/networks/{networkId}/changes/{eventId}``
     - Update an event. Body: ``{ "reviewed": boolean, "notes": "string" }`` (both optional).

Baseline Definitions
~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 55 35

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/monitor/networks/{networkId}/baseline/definitions``
     - List all baseline definitions for a network.
   * - ``POST``
     - ``/api/v1/monitor/networks/{networkId}/baseline/definitions``
     - Create a definition. Body: ``{ "entryType": "DEVICE|IP_MAC_BINDING|GATEWAY|PROTOCOL|APP|VPN_FINGERPRINT", "entityKey": "string", "entityValue": "string?", "notes": "string?" }``.
   * - ``DELETE``
     - ``/api/v1/monitor/networks/{networkId}/baseline/definitions/{definitionId}``
     - Delete a baseline definition.

Subnet Definitions
~~~~~~~~~~~~~~~~~~

Subnets are global (not per-network). All endpoints are prefixed with ``/api/v1/subnets``.

.. list-table::
   :header-rows: 1
   :widths: 10 45 45

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/subnets``
     - List all saved subnets, ordered by CIDR.
   * - ``POST``
     - ``/api/v1/subnets``
     - Create or update a subnet by CIDR. Body: ``{ "cidr": "string", "label": "string?", "description": "string?", "confirmed": boolean }``. Sets ``source = MANUAL``.
   * - ``POST``
     - ``/api/v1/subnets/detected``
     - Save an auto-detected subnet candidate. Same body; sets ``source = AUTO``.
   * - ``DELETE``
     - ``/api/v1/subnets/{id}``
     - Delete a subnet definition by ID.
   * - ``GET``
     - ``/api/v1/subnets/detect?fileId={fileId}``
     - Infer subnet candidates from a single PCAP. Returns candidates without persisting.
   * - ``GET``
     - ``/api/v1/subnets/detect/network?networkId={networkId}``
     - Infer subnet candidates across all snapshots in a network, with consistency scores.

Node Roles
~~~~~~~~~~

Node roles are global. All endpoints are prefixed with ``/api/v1/node-roles``.

.. list-table::
   :header-rows: 1
   :widths: 10 55 35

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/node-roles?entityType={type}&entityKey={key}``
     - Get the role for a specific entity. Returns 204 if none exists.
   * - ``PUT``
     - ``/api/v1/node-roles``
     - Create or update a role. Body: ``{ "entityType": "IP|DEVICE", "entityKey": "string", "roleLabel": "string?", "roleDescription": "string?", "confirmedByHuman": boolean }``.
   * - ``DELETE``
     - ``/api/v1/node-roles?entityType={type}&entityKey={key}``
     - Delete a role.
   * - ``POST``
     - ``/api/v1/node-roles/suggest?entityType={type}&entityKey={key}&fileId={fileId}``
     - Ask the LLM to suggest a role based on traffic signals. Returns an unconfirmed suggestion.

External Events
~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 55 35

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/monitor/networks/{networkId}/external-events``
     - List all external events for a network, ordered by event time descending.
   * - ``POST``
     - ``/api/v1/monitor/networks/{networkId}/external-events``
     - Create an event. Body: ``{ "eventTime": "ISO-8601", "title": "string", "description": "string?" }``.
   * - ``DELETE``
     - ``/api/v1/monitor/networks/{networkId}/external-events/{eventId}``
     - Delete an external event.

Analyst Annotations
~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 55 35

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/monitor/networks/{networkId}/annotations``
     - List annotations, newest first.
   * - ``POST``
     - ``/api/v1/monitor/networks/{networkId}/annotations``
     - Create an annotation. Body: ``{ "body": "string", "snapshotId": "uuid?" }``.
   * - ``PATCH``
     - ``/api/v1/monitor/networks/{networkId}/annotations/{annotationId}``
     - Update annotation body. Body: ``{ "body": "string" }``.
   * - ``DELETE``
     - ``/api/v1/monitor/networks/{networkId}/annotations/{annotationId}``
     - Delete an annotation.

Network Insights
~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 55 35

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/monitor/networks/{networkId}/insights/latest``
     - Get the most recently generated insight. Returns 204 if none exists.
   * - ``POST``
     - ``/api/v1/monitor/networks/{networkId}/insights/generate``
     - Generate a new insight. Body: ``{ "audience": "TECHNICAL|EXECUTIVE|OT", "focus": "SECURITY|OPERATIONAL|COMPLIANCE" }`` (both optional; defaults to TECHNICAL / SECURITY).

Per-Snapshot Insights
~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 65 25

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/monitor/networks/{networkId}/snapshots/{snapshotId}/insights/latest``
     - Get the latest insight for a snapshot. Returns 204 if none exists.
   * - ``POST``
     - ``/api/v1/monitor/networks/{networkId}/snapshots/{snapshotId}/insights/generate``
     - Generate a snapshot-scoped insight. Same body as network insights.

Entity Notes
~~~~~~~~~~~~

Entity notes are global (not per-network). All endpoints are prefixed with ``/api/v1/entity-notes``.

.. list-table::
   :header-rows: 1
   :widths: 10 55 35

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/entity-notes?entityType={type}&entityKey={key}``
     - Get the note for a specific entity. Returns 204 if none exists.
   * - ``PUT``
     - ``/api/v1/entity-notes``
     - Create or update a note. Body: ``{ "entityType": "IP|DEVICE|PROTOCOL|APPLICATION", "entityKey": "string", "note": "string" }``.
   * - ``DELETE``
     - ``/api/v1/entity-notes?entityType={type}&entityKey={key}``
     - Delete a note.

Private IP Overrides
~~~~~~~~~~~~~~~~~~~~

Overrides are global (not per-network). All endpoints are prefixed with
``/api/v1/custom-private-ranges``.

.. list-table::
   :header-rows: 1
   :widths: 10 45 45

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/v1/custom-private-ranges``
     - List all private IP overrides.
   * - ``POST``
     - ``/api/v1/custom-private-ranges``
     - Create an override. Body: ``{ "cidr": "string", "label": "string?" }``.
       A bare IP (e.g. ``"203.0.113.42"``) is automatically normalised to
       ``/32`` (or ``/128`` for IPv6). Returns 400 if the CIDR is invalid or
       already exists.
   * - ``DELETE``
     - ``/api/v1/custom-private-ranges/{id}``
     - Delete an override by ID.
