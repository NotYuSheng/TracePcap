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
   * - **Node colour and icon**
     - Node colour and icon are derived from two classification signals.
       **Specific service nodes** (DNS server, web server, SSH server, etc.)
       always use their service colour. **Generic nodes** (``client`` /
       ``unknown``) use the hardware device classification colour instead
       (IoT = pink, Mobile = violet, Laptop/Desktop = blue, Server = emerald,
       Router = orange). The legend in the graph reflects exactly which colours
       are present in the current view. See the *Classification* section below
       for how each signal is derived.
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

The graph is rendered with **Sigma.js** (WebGL) using **graphology** as the
underlying graph model. No external tile servers or map services are used — the
topology is a pure data-driven graph rendered in the browser.

Two layout algorithms are available:

- **Force-directed** (default) — ForceAtlas2 run in a Web Worker, followed by
  a de-overlapping pass. Surfaces natural clusters and hub-and-spoke structure.
- **Hierarchical** — ELK (Eclipse Layout Kernel) ``layered`` algorithm, which
  implements the **Sugiyama method**: nodes are ranked into horizontal layers by
  longest-path analysis, edge crossings between layers are minimised, and
  disconnected components are placed side-by-side. This layout makes
  client → server traffic flow and parent/child relationships immediately
  visible.

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

Ghost / Phantom Node Filters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some nodes appear in the graph only because a host *probed* them — the address
never actually sent traffic back. These **ghost** (phantom) nodes are detected
at graph-build time and flagged so you can hide them and focus on hosts that are
genuinely present. Four flag types are detected:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Flag
     - Meaning
   * - **No response**
     - The node only ever appeared as a destination — all traffic was
       unidirectional toward it, with nothing coming back
       (``flowRisks: ["unidirectional_traffic"]``).
   * - **ARP no-reply**
     - The host was ARP-requested but never replied — a classic ARP-scan
       artifact where the target IP is unused.
   * - **ICMP unreachable**
     - An ICMP *destination unreachable* was observed for the node.
   * - **TTL exceeded**
     - An ICMP *time-to-live exceeded* was observed (e.g. a traceroute hop, not
       a real conversation endpoint).

The **Ghost Node Filters** section in the control panel only shows the flag
types actually present in the current capture. Each is a pill that toggles a
**hide** filter — selecting it removes nodes carrying that flag from the graph.
A ghost-flag banner in the Node Detail modal explains why a node was flagged.
The active ghost filters are also honoured when exporting the topology to a PDF
report.

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

**Type** — the node's network topology role, derived from traffic analysis.
Classification priority (highest first):

1. **nDPI application name** — the most reliable signal, works even on
   non-standard ports and encrypted flows. Recognised apps:
   DNS, HTTP, TLS/QUIC, SSH, FTP, SMTP/IMAP/POP, DHCP, NTP, and common
   databases (MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch).
2. **Well-known port / protocol** — fallback when nDPI app is unavailable
   (e.g. port 443/TCP → web server, port 22/TCP → SSH server).
3. **Router heuristic** — a node with 10 or more distinct peers that is
   not acting as a server is classified as a Router / Gateway.
4. **Role fallback** — nodes that match none of the above are classified
   as ``Client`` (default for most endpoints) or ``Unknown``.

Node colour in the graph reflects which tier matched:

- **Specific service types** (dns-server, web-server, ssh-server, etc.)
  always use their service colour regardless of device classification.
- **Generic types** (``client``, ``unknown``) show the **device type colour**
  instead — so an IoT client appears pink and a mobile client appears violet,
  making hardware diversity visible without requiring a separate filter.

Evidence text is shown below the badge (e.g. "42 distinct peers" for a
router, or the nDPI applications that triggered the classification).

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

Service-Role Detection
~~~~~~~~~~~~~~~~~~~~~~~

Beyond the port/protocol heuristics above, TracePcap runs dedicated
**service-role extractors** during analysis that inspect what a host actually
*serves* and classify it authoritatively. These drive distinct device types,
node colours, and icons in the topology, and add a service-specific detail tab
to the node modal:

- **DNS server** (``DNS_SERVER``) — a host that answers DNS queries. Detected by
  ``DnsServerSignal`` from observed DNS responses.
- **Web server** (``WEB_SERVER``) — serves cleartext HTTP, or is HTTPS-only
  (detected from a TLS ServerHello).
- **API server** (``API_SERVER``) — a web server whose responses look like an
  API (JSON content, REST verbs, or ``/api`` paths).

Service Role Detail Tabs
~~~~~~~~~~~~~~~~~~~~~~~~~

When a node is classified into a service role, its detail modal gains an extra
tab populated from a read-only analysis pass:

**DNS tab** — a per-host **DNS query log**: the domains the server answered,
record type, and response counts, aggregated per ``(server, domain, type)``.
Servers with abnormally high NXDOMAIN rates are flagged (a signal for DNS
tunnelling or misconfigured clients). Each row links to the source DNS response
packet.

**HTTP tab** — a per-host **HTTP endpoint log** recovered by correlating
cleartext HTTP requests to responses per TCP stream (method + path), with
status-class counts and content type per endpoint. An info block above the
table shows the ``Server`` header software, observed content types, and — for
HTTPS hosts — **TLS details** reconstructed from existing conversation
enrichment (SNI names, certificate subject/issuer, JA3S). Each endpoint row
links to its source packet.

.. note::
   Endpoint recovery is cleartext HTTP/1.x only — HTTPS payloads are encrypted,
   so HTTPS-only hosts surface TLS metadata but no endpoint table.

Node Label Customization
------------------------

You can control what text is **tagged onto each node** in the topology graph.
Open the **Node Label** settings to choose which fields render as label lines
beneath a node — for example IP address, hostname (auto-tagged from the TLS SNI
/ ClientHello), MAC address, vendor, or device type. A live preview shows the
chosen layout, and the configuration applies to every node in the graph.

Hostnames are tagged passively: when a client's name is observed in traffic it
is attached to the node and available as a label field, with no active probing.

Layout Controls
---------------

- **Force-directed** — switch to ForceAtlas2 layout (default).
- **Hierarchical** — switch to ELK Sugiyama layered layout (top-down).
- **Fit view** — reset the camera to fit all nodes in the viewport.
- **Filters** — open the filter panel (also accessible in fullscreen mode).

Export
------

The topology can be captured as part of the PDF report via the **Export PDF**
button (see :doc:`../operations/backup-restore`).
