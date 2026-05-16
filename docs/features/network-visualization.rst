Network Visualization
=====================

The Network Visualization tab renders an interactive topology graph of all
hosts and flows extracted from the PCAP file.

How the Graph Is Constructed
-----------------------------

The graph is derived entirely from the conversations stored in the database
after analysis. No additional network probing or external lookups are performed
at graph render time.

Node Construction
~~~~~~~~~~~~~~~~~

Each unique IP address that appears as either ``srcIp`` or ``dstIp`` in any
conversation becomes a **node**. For non-IP Layer-2 traffic (ARP, STP, LLDP,
CDP, etc.), the node identifier is:

- For ARP frames: the IP address embedded in the ARP payload
  (``arp.src.proto_ipv4`` / ``arp.dst.proto_ipv4``).
- For other pure Layer-2 frames: the Ethernet MAC address (``eth.src`` /
  ``eth.dst``), because there is no IP address to use.

A single PCAP can therefore contain both IP nodes and MAC-address nodes if it
captures a mix of Layer-3 and Layer-2 traffic.

Edge Construction
~~~~~~~~~~~~~~~~~

Each unique conversation (5-tuple after direction-normalization — see
:doc:`conversations`) becomes an **edge** between its two endpoint nodes. If
two IPs have multiple conversations (e.g. TCP on port 443 and TCP on port 80),
they produce multiple edges — one per conversation row.

Edge thickness is fixed: **1.5 px** for edges in a single capture, or **2.5 px**
for edges that appear in both captures when using the Compare view. Edge width
does not vary with traffic volume.

Node Attributes and Their Sources
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each node's visual appearance and detail-panel data come from the following
sources:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Attribute
     - Source
   * - **IP address**
     - ``srcIp`` or ``dstIp`` field from the conversation table.
   * - **MAC address**
     - The first-seen ``eth.src`` (Ethernet source MAC) for that IP, recorded
       during the tshark parsing pass. Only populated if the host is
       Layer-2-adjacent to the capture point; MAC addresses are not visible
       for hosts on the other side of a router.
   * - **Vendor**
     - The MAC address OUI prefix (first 3 octets) resolved against the bundled
       Wireshark ``manuf`` database. Shown in the Node Detail Panel. Not
       available if the MAC address is absent, locally-administered
       (randomised), or belongs to a virtual adapter.
   * - **Device type icon**
     - The predicted device type from the multi-signal classifier (OUI, TTL,
       nDPI apps, traffic patterns). See :doc:`geolocation` for the full
       scoring algorithm. A ``device_type`` override in a custom signature rule
       sets the icon to 100% confidence.
   * - **Country flag**
     - Shown on external (non-RFC-1918) IP nodes only. Sourced from ipinfo.io
       (online) or the bundled DB-IP Lite MMDB (offline fallback). RFC-1918,
       loopback, and link-local addresses are marked "Private" and display no
       flag.
   * - **Risk indicator**
     - A warning badge appears if any conversation involving this node has one
       or more nDPI risk flags (e.g. ``TLS Self Signed Certificate``,
       ``Suspicious Entropy``).
   * - **ASN**
     - Autonomous System number and organisation name, available only when
       the ipinfo.io source was used (not available from the MMDB fallback).

Technology
----------

The graph is built with **React Flow** and laid out using the **ELK** (Eclipse
Layout Kernel) automatic layout engine. No external tile servers or map
services are used — the topology is a pure data-driven graph rendered in the
browser.

Grouping Modes
--------------

The visualization supports several grouping modes that cluster nodes together:

- **Individual IP** (default) — one node per IP address.
- **ASN** — nodes sharing the same Autonomous System are grouped into a cluster
  node. Only available for IPs enriched via ipinfo.io (ASN is not available
  from the MMDB fallback).
- **Country** — nodes grouped by country code from the geo lookup.
- **City** — nodes grouped by city from the geo lookup.
- **Device type** — nodes grouped by predicted device class.
- **Custom network label** — user-defined CIDR labels (configured separately)
  group IPs that fall within each CIDR range.

Filter Panel
------------

The filter panel (left sidebar) lets you narrow the graph by:

- Source / destination IP
- Port
- Device type
- Protocol
- Application (nDPI)
- Risk level
- Custom signature match
- Country

Filters are applied interactively — the graph updates without reloading.

Click a node to open the **Node Detail Panel**, which shows:

- IP address and MAC address
- Hostname (SNI extracted from TLS ClientHello, if available)
- Classification badge — click it to open the **Classification popup** (see
  below)
- Packets sent / received and bytes sent / received / total
- Protocols used across all conversations
- Connections table: per-peer breakdown sorted by bytes, with application labels

Classification Popup
~~~~~~~~~~~~~~~~~~~~

Clicking the classification badge opens a popup with three sections:

**Type** — the node's network topology role, derived from traffic analysis:

- ``Router`` — many distinct peers (flagged by peer-count threshold)
- ``Server`` — receives inbound connections on well-known ports
- ``Client`` — initiates connections (default for most endpoints)
- Evidence text shown below the badge (e.g. "42 distinct peers", or the
  nDPI applications that triggered the classification)

**Device** — the hardware/OS classification from the multi-signal scorer
(see :doc:`geolocation` for the full algorithm):

- The device type badge (e.g. ``Mobile``, ``Router``, ``IoT Device``)
- A bullet list of the signals that contributed:

  - ``MAC OUI matched: <vendor>`` — OUI resolved to a known vendor
  - ``TTL <N> → <OS family>`` — observed TTL mapped to Linux/Android/iOS,
    Windows, or Network device (Cisco/BSD)
  - ``Application traffic profile analysed`` — shown when confidence ≥ 60
  - ``Network traffic patterns analysed`` — shown when confidence ≥ 25

- A **confidence progress bar** showing the numeric confidence percentage
  and a qualitative label:

  - **Strong** — ≥ 75%
  - **Moderate** — ≥ 50%
  - **Low** — ≥ 25%
  - **Uncertain** — < 25%

  The confidence is computed from the score margin between the winning device
  type and the runner-up: ``min(100, round(margin × 100 / 60))``. A margin of
  60 or more points → 100% (Strong). A tie → 0% (Uncertain).

**Role** — whether this host initiates or receives connections:

- ``Client`` — mostly initiates
- ``Server`` — mostly receives
- ``Both`` — significant traffic in both directions
- Counts of conversations initiated vs. received are shown below the badge

A legend table at the bottom of the popup summarises the signal source for
each classification dimension (Type: network topology; Device: hardware
fingerprinting; Role: TCP session direction).

Layout Controls
---------------

- **Auto layout** — re-run ELK layout.
- **Fullscreen toggle** — expand the graph to fill the viewport.
- **Zoom controls** — zoom in/out and fit-to-screen buttons.

Export
------

The topology can be captured as part of the PDF report via the **Export PDF**
button (see :doc:`../operations/backup-restore`).
