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
does not vary with traffic volume — volume is carried by color instead, when the
**Color edges by** control is set to Volume (see below).

Edge Color Modes
~~~~~~~~~~~~~~~~

The **Color edges by** control above the diagram switches what edge color means:

- **Protocol** (default) — each edge takes its protocol's color.
- **Volume** — each edge is shaded by its ``totalBytes`` on the
  :ref:`shared volume color scale <shared-volume-scale>`, the same scale the
  node-to-node heatmap uses. A gradient legend appears beside the control.

These are alternatives rather than layers. Color is a single channel, and
encoding two meanings in it at once would make neither readable — so only one is
active at a time, and whichever is active is accompanied by its legend.

Switching modes repaints the edges in place; it does not re-run the layout, so
node positions are preserved.

The control is available in both the analysis-mode diagram and the monitor-mode
snapshot diagram, which share the same underlying graph component.

Node-to-Node Volume Heatmap
---------------------------

Below the diagram, the **Node-to-Node Volume** panel renders a src×dst matrix of
the displayed hosts, each cell shaded by the volume between that pair on the
:ref:`shared volume color scale <shared-volume-scale>`. The diagram answers
*who talks to whom*; the matrix answers *how much*, which a force-directed
layout cannot show — a hairball is the wrong shape for "which pair is loudest".

Key properties:

- **Same data as the diagram.** The matrix is aggregated from exactly the
  filtered edges the diagram is rendering, so filtering the diagram re-fits the
  matrix too. Note the two aggregate at different levels: a cell is the total
  across every conversation between a pair, whereas the diagram draws one edge
  per protocol/app. For a single-protocol pair a cell and its edge are the same
  number; for a multi-protocol pair the cell is the sum of its edges. Each view
  normalizes against its own maximum, so compare within a view.
- **Busiest-first ordering.** Rows and columns are sorted by total volume, so
  the dark cells cluster toward the top-left and the shape of the matrix itself
  carries information.
- **Renders every host.** The grid is drawn to a ``<canvas>``, not a table, so it
  is not limited the way a DOM grid would be — a 500-host capture is 250,000
  cells, which as DOM nodes would freeze the tab. Because the matrix is *sparse*,
  only pairs that actually exchanged traffic are drawn, so cost scales with the
  number of conversations rather than with N². A sanity cap of 1000 hosts applies;
  beyond that a cell is under a pixel. Any hosts dropped by that cap are the
  *quietest*, since the axes are ordered by volume.
- **Fits, then zooms.** Cell size is fitted to the panel width (2–22px). At high
  host counts the matrix becomes a dense overview texture where block structure
  and hotspots are the signal, and axis labels drop out below 9px per cell. The
  zoom control trades that overview for an inspectable grid that scrolls, and
  fullscreen gives the fitted view more room — 100 hosts fit with labels at
  17px per cell in fullscreen, versus 10px in the inline panel.
- **Cross-filtering.** Clicking a cell highlights that pair in the diagram;
  selecting a node in the diagram emphasizes its row and column in the matrix.
- **Axis labels are IP addresses**, shown when cells are at least 9px, and
  clicking one opens that host's details panel. IPs are used rather than identity
  or device-type labels because those are not unique — two hosts can carry the
  same one, which on a matrix axis would leave two rows that cannot be told
  apart. Hosts with no IP (L2-only nodes) fall back to their MAC. Hovering a
  cell shows the fuller identity of both endpoints — hostname and adjudicated
  identity where known — in the readout beneath the grid.

The panel appears in two places, with the same canvas rendering, zoom and
fullscreen in both:

- the **Network Topology Diagram** tab in analysis mode
  (``/analysis/<fileId>/network-diagram``), below the diagram;
- the **Network Diagram** tab of the snapshot dialog in monitor mode, reached
  from **Capture Timeline** on a network's detail page.

The one difference is where fullscreen stacks: from the snapshot dialog it must
sit *above* the modal containing it, so it uses its own overlay rather than the
shared card treatment. In the dialog the panel is collapsed by default, since
that view is already dense and the diagram is the primary subject.

.. note::

   Cells are directed (row = source, column = destination), but each
   conversation's ``totalBytes`` covers **both** directions of that exchange. A
   cell therefore reads as "volume of the exchanges this host initiated", not
   "bytes this host sent". Separating the two requires per-direction counters,
   which are not yet captured.

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
- **Identity** — the adjudicated verdict for "what is this host?" (see below)
- **Evidence weighed** — the measured facts behind the verdict (see below)
- **Role** — the analyst-assigned name for the host (e.g. *Finance DB*)
- Packets sent / received and bytes sent / received / total
- Protocols used across all conversations
- Connections table: per-peer breakdown sorted by bytes, with application labels

Identity & Evidence (facts → votes → verdict)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Host classification follows a **facts → votes → verdict** model. The browser
never classifies; it renders the backend's adjudication (see
:doc:`../architecture/adjudication-explainability`).

**Identity (the verdict)** — one adjudicated answer per host, with:

- The winning device type (e.g. ``Mobile``, ``Router``, ``Web Server``), its
  **confidence** (computed from the score margin between winner and runner-up:
  ``min(100, round(margin × 100 / 60))``), and a **⚠ contested** marker when
  the margin is too small to assert a winner.
- **Why** — every candidate type with its score and the human-readable reasons
  that voted for it (e.g. ``Mobile app "WhatsApp" → +20`` toward ``MOBILE``).
  One fact can support several candidates.
- **I disagree** — a first-class human override that sets the verdict.
- **Add evidence** — an analyst-contributed weighted signal that re-enters the
  vote (it informs, it does not override).

**Evidence weighed (the facts)** — three read-only rows listing what was
*measured*, with no scores and no per-axis conclusion (conclusions belong to
Identity alone):

- **Hardware** — the physical fingerprint: MAC OUI manufacturer and observed
  TTL.
- **Ports / Service** — what the host does on the wire: a confirmed service
  role (DNS/Web/API, detected from its actual responses), or the application
  nDPI identified in its traffic when no service was detected.
- **Behaviour** — measured connection direction (who sent the TCP SYN, #496):
  how many connections the host opened vs. answered. Flows with no measured
  initiator (UDP, mid-stream captures) count toward neither — unknown is
  reported as "Nothing observed", never guessed.

When the observed service evidence contradicts the Identity verdict (e.g. a
host that demonstrably served HTTP while the verdict says IoT endpoint), an
**Evidence conflicts** banner flags it for analyst review.

Node colour in the graph follows the adjudicated identity: service verdicts
(dns-server, web-server, …) use their service colour; generic endpoints show
the device-type colour, making hardware diversity visible without a separate
filter.

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
  API (JSON content, REST verbs, or ``/api`` paths). An ``API_SERVER`` is a
  specialisation of the web role and reuses the same **HTTP tab** described
  below — there is no separate API tab.

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
beneath a node — the analyst-assigned **role** (e.g. *Finance DB*; confirmed
labels only, shown by default), IP address, hostname (auto-tagged from the TLS
SNI / ClientHello), MAC address, vendor, or device type. A live preview shows
the chosen layout, and the configuration applies to every node in the graph.

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
