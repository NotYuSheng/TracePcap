Network Monitor
===============

The Network Monitor provides SOC-style change detection across a chronological
series of PCAP snapshots. It answers the question: *what changed on this
network between these two captures?*

Rather than analysing a single file in isolation, you group related PCAPs into
a **Network**, add them as **Snapshots**, and let the engine compare consecutive
snapshots to surface behavioural changes as prioritised **Change Events**.

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
  snapshot.

Getting Started
---------------

1. Navigate to **Monitor** in the top navigation bar.
2. Click **Create Network** and give it a name and optional description.
3. Open the network card to enter the detail view.
4. Click **Add Snapshot** and select a PCAP file that has already been
   analysed (status: *Completed*). Repeat for each capture.
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

- **Severity** — CRITICAL, WARNING, INFO
- **Change type** — MAC_ADDED, IP_MAC_DRIFT, ASN_CHANGE, GATEWAY_CHANGE,
  PROTOCOL_ADDED, APP_ADDED, VPN_DRIFT
- **Reviewed status** — hide reviewed events to focus on open items

The badge count in the filter bar reflects the current filter selection.

Marking as Reviewed
~~~~~~~~~~~~~~~~~~~

Click the checkbox on any event to mark it as reviewed. Add a note to record
the reason (e.g. "Known DHCP lease renewal — expected"). The network card
unreviewed counts update immediately.

Drift Panels
------------

Three drift panels on the network detail page give a cross-snapshot summary:

Devices Panel
~~~~~~~~~~~~~

Shows all MAC addresses seen across all snapshots. Each device badge is
colour-coded (deterministic hue per MAC). Click a badge to open the **Device
History Modal**, which shows:

- IP address history across snapshots (paginated; use arrow keys to page)
- Protocols and applications observed per snapshot
- **How this is derived** — the classification signals and confidence score
  for the device type prediction

Absent devices (not seen in the latest snapshot) appear greyed-out with
strikethrough. Click an absent badge to see when the device was last observed.

Protocols & Applications Panel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Shows all protocols and nDPI application names seen across all snapshots,
split into two groups. Colour-coded by name hash. Absent entries (not seen in
the latest snapshot) are shown greyed-out with strikethrough and open a
**Last Seen** modal on click.

IP Addresses Panel
~~~~~~~~~~~~~~~~~~

Shows all IP addresses observed in conversation endpoints across all snapshots,
split into:

- **Private** — RFC 1918, loopback, and link-local addresses
- **Public** — all other addresses

Absent addresses follow the same greyed-out / strikethrough pattern.

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

Network Diagram Overlay
-----------------------

The **Network Diagram** tab on the network detail page renders the topology
graph for any selected snapshot. Change events are overlaid as coloured
highlights:

- Red nodes/edges — CRITICAL events
- Yellow nodes/edges — WARNING events
- Blue nodes/edges — INFO events

Use the snapshot selector to step through the timeline and see how the topology
evolved. Nodes involved in change events are labelled with the event type.

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

All endpoints are prefixed with ``/api/monitor``.

Networks
~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 35 55

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/monitor/networks``
     - List all networks.
   * - ``GET``
     - ``/api/monitor/networks/{networkId}``
     - Get a single network by ID.
   * - ``POST``
     - ``/api/monitor/networks``
     - Create a network. Body: ``{ "name": "string", "description": "string" }``.
   * - ``DELETE``
     - ``/api/monitor/networks/{networkId}``
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
     - ``/api/monitor/networks/{networkId}/snapshots``
     - List snapshots ordered by capture time.
   * - ``POST``
     - ``/api/monitor/networks/{networkId}/snapshots``
     - Add a snapshot. Body: ``{ "fileId": "uuid" }``. Triggers change detection automatically.
   * - ``DELETE``
     - ``/api/monitor/networks/{networkId}/snapshots/{snapshotId}``
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
     - ``/api/monitor/networks/{networkId}/changes``
     - List change events. Optional query params: ``changeType``, ``severity``.
   * - ``PATCH``
     - ``/api/monitor/networks/{networkId}/changes/{eventId}``
     - Update ``reviewed`` (boolean) and/or ``notes`` (string) on an event.

Baseline Definitions
~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 55 35

   * - Method
     - Path
     - Description
   * - ``GET``
     - ``/api/monitor/networks/{networkId}/baseline/definitions``
     - List all baseline definitions for a network.
   * - ``POST``
     - ``/api/monitor/networks/{networkId}/baseline/definitions``
     - Create a definition. Body: ``{ "entryType": "DEVICE|IP_MAC_BINDING|GATEWAY|PROTOCOL|APP|VPN_FINGERPRINT", "entityKey": "string", "entityValue": "string", "notes": "string" }``.
   * - ``DELETE``
     - ``/api/monitor/networks/{networkId}/baseline/definitions/{definitionId}``
     - Delete a baseline definition.
