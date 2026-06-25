Conversations
=============

The Conversations tab lists every network flow (conversation) extracted from
the PCAP file — one row per unique bidirectional flow.

How Conversations Are Built
----------------------------

Understanding exactly how TracePcap groups packets into conversations prevents
misreading the data.

Packet Extraction
~~~~~~~~~~~~~~~~~

TracePcap invokes ``tshark`` once per PCAP with 19 ``-e`` field selectors and
pipe-separated output:

.. code-block:: text

   tshark -r <file> -T fields -E separator=| \
     -e frame.time_epoch \
     -e frame.len \
     -e ip.src \
     -e ip.dst \
     -e ipv6.src \
     -e ipv6.dst \
     -e tcp.srcport \
     -e tcp.dstport \
     -e udp.srcport \
     -e udp.dstport \
     -e _ws.col.Protocol \
     -e _ws.col.Info \
     -e tcp.payload \
     -e udp.payload \
     -e ip.ttl \
     -e eth.src \
     -e arp.src.proto_ipv4 \
     -e arp.dst.proto_ipv4 \
     -e eth.dst

Fields (in order): Unix epoch timestamp, on-wire frame length, IPv4 src/dst,
IPv6 src/dst (fallback), TCP src/dst port, UDP src/dst port, Wireshark Protocol
display column, Wireshark Info display column, TCP payload bytes (colon-hex),
UDP payload bytes, IP TTL, Ethernet source MAC, ARP sender/target IPs,
Ethernet destination MAC.

For **IPv4** traffic, ``ip.src``/``ip.dst`` are used. For **IPv6**, the service
falls back to ``ipv6.src``/``ipv6.dst``. For **ARP** frames (no IP layer),
the IP addresses embedded in the ARP payload (``arp.src.proto_ipv4`` /
``arp.dst.proto_ipv4``) are used as node identifiers. For other non-IP Layer-2
frames (STP, LLDP, CDP), the Ethernet MAC addresses themselves become the node
identifiers since there are no IP addresses to extract.

If tshark returns comma-separated values for a field (which can happen with
tunnelled or multi-layer packets), only the **first** value is used.

The ``protocol`` field is ``_ws.col.Protocol`` uppercased and truncated to 20
characters. This is Wireshark's "Protocol" display column — the highest
protocol layer that Wireshark's dissectors recognised for that packet. It is
**not** always the same as the nDPI ``appName`` (see `Protocol vs Application`_
below).

Conversation Grouping Key
~~~~~~~~~~~~~~~~~~~~~~~~~

Packets are merged into a single conversation if they share the same
**direction-independent 5-tuple**. The key is computed as follows:

1. Compare ``srcIp`` and ``dstIp`` lexicographically.
2. If ``srcIp < dstIp``: the canonical form is ``srcIp:srcPort-dstIp:dstPort``.
3. If ``srcIp > dstIp``: swap, so the canonical form is ``dstIp:dstPort-srcIp:srcPort``.
4. If the IPs are equal (same-host loopback traffic): compare ports — the
   smaller port number goes first.

This means a packet from ``10.0.0.1:55000`` → ``10.0.0.2:443`` and a reply from
``10.0.0.2:443`` → ``10.0.0.1:55000`` are **counted in the same conversation
row**. The ``srcIp``/``dstIp`` shown in the UI are from the **first packet** that
created the conversation entry, not necessarily the initiating direction.

The full key format is: ``ip1:port1-ip2:port2-PROTOCOL``.

Packet Count and Byte Count
~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Packet count**: the number of tshark output lines (i.e., raw frames) that
  matched the conversation key. Both directions are counted together.
- **Byte count**: the sum of ``frame.len`` values for all packets in the
  conversation. ``frame.len`` is the **total on-wire frame length** including
  all headers (Ethernet, IP, TCP/UDP) and the payload. It reflects what
  actually appeared on the wire, not just the application-layer payload.

Start Time and End Time
~~~~~~~~~~~~~~~~~~~~~~~

- **Start time**: the ``frame.time_epoch`` of the first packet that matched this
  conversation's key, converted to the server's local timezone.
- **End time**: the ``frame.time_epoch`` of the last packet that matched this
  conversation's key.

These timestamps come directly from the PCAP frame timestamps, which are set
by the capturing host's clock at the moment each packet was recorded. They do
not reflect any clock synchronisation — if the capture machine's clock was
skewed, all timestamps will be skewed equally.

Payload Storage
~~~~~~~~~~~~~~~

For each packet, the first **64 bytes** of the TCP or UDP application payload
are stored as a lowercase hex string. This is used by:

- **Custom signature** ``payload_contains`` matching (searches each packet's
  stored hex in turn).
- **Session Reconstruction** (which runs a separate ``tshark -z follow`` pass
  to get the full reassembled stream — the 64-byte limit does not affect
  reconstruction).

Protocol vs Application
-----------------------

The Conversations table has two distinct protocol-related columns. Understanding
the difference is important for correctly interpreting the data:

``protocol`` — Wireshark Display Column Label
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sourced from ``_ws.col.Protocol`` (tshark's "Protocol" display column).

- This is the **transport/network-layer label** Wireshark assigns to the frame
  based on its dissector stack — e.g. ``TCP``, ``UDP``, ``ICMP``, ``TLS``,
  ``DNS``, ``HTTP``.
- It is set at **packet-parse time** from the first tshark pass, before nDPI
  runs.
- A subsequent enrichment pass (see ``tsharkProtocol`` below) refines this
  using the ``frame.protocols`` stack.
- Examples: ``TLS``, ``TCP``, ``DNS``, ``MDNS``, ``HTTP``, ``QUIC``.

``tsharkProtocol`` — Deepest Dissector Stack Label
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In a second tshark pass, ``TsharkEnrichmentService`` extracts the
``frame.protocols`` field for every packet. This field is the full protocol
dissector stack as a colon-separated string, e.g.:

.. code-block:: text

   eth:ethertype:ip:tcp:http
   eth:ethertype:ip:udp:dns
   eth:ethertype:ip:tcp:tls
   eth:ethertype:ip:tcp:data

The service takes the **rightmost (deepest)** component as the application-layer
label and uppercases it (``http`` → ``HTTP``). It discards:

- The known L4 transport proto (e.g. if L4 is TCP, a top-of-stack ``TCP`` is
  suppressed — it means Wireshark couldn't dissect further).
- Generic labels: ``DATA``, ``FRAME``, ``ETH``, ``ETHERNET``, ``SLL``, ``RAW``
  (these indicate Wireshark reached the end of its dissectors with no app-layer
  identification).

Across all packets in a conversation, the **most frequently seen** app-layer
label wins and is stored as ``tsharkProtocol``.

``appName`` — nDPI Application Identity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set by the nDPI analysis pass (``NdpiService``). This is a **traffic
classification** result, not a dissector label. nDPI identifies the application
from patterns in the entire flow, even through encryption — e.g.:

- ``YouTube`` (HTTPS traffic to Google CDN with YouTube signatures)
- ``WhatsApp`` (encrypted WhatsApp media or voice)
- ``BitTorrent`` (even when using non-standard ports)
- ``TOR`` (characteristic TOR circuit patterns)

``appName`` and ``tsharkProtocol`` are **complementary**:

- ``tsharkProtocol = TLS``, ``appName = YouTube`` means: the transport is TLS
  (Wireshark can see the TLS handshake), and nDPI has classified the application
  as YouTube (from fingerprints within the encrypted stream).
- ``tsharkProtocol = QUIC``, ``appName = Unknown`` means: the transport is QUIC
  but nDPI could not identify the application.
- Both fields absent means the traffic was too short or too ambiguous for either
  system to classify.

Columns
-------

The column set is configurable via the **Column Picker** button. Default
columns include:

- Source IP / Destination IP — from the first packet creating the conversation
- Source Port / Destination Port
- Protocol — ``_ws.col.Protocol`` label (see `Protocol vs Application`_)
- Application (nDPI) — nDPI ``appName``
- Category (nDPI) — nDPI traffic category (e.g. ``Social Network``, ``Media``)
- Wireshark Protocol — ``tsharkProtocol`` from the ``frame.protocols`` stack
- Risk flags — nDPI risk identifiers (e.g. ``TLS Self Signed Certificate``)
- IDS Alerts — Suricata signature matches for the conversation, shown as purple
  badges (only present when Suricata was enabled for the file; see
  :doc:`ids-threat-detection`)
- Country (src / dst) — from ipinfo.io or DB-IP MMDB lookup
- Device type (src / dst) — from the multi-signal device classifier
- Bytes transferred — sum of ``frame.len`` for all matched packets
- Packet count — number of matched frames (both directions)
- Start / end timestamp — from PCAP frame timestamps
- Custom signature matches — names of fired custom detection rules
- HTTP User-Agent — extracted from ``http.user_agent`` tshark field

Filtering
---------

The filter panel supports simultaneous filtering. Each filter section has a
clickable ⓘ icon that explains exactly what is being matched. Filters combine
with AND logic — a conversation must satisfy all active filters to be shown.

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Filter
     - What it matches
   * - **IP / Hostname**
     - Substring match (case-insensitive) against ``srcIp``, ``dstIp``, or the
       SNI hostname extracted by nDPI. Accepts partial IPs or hostnames.
   * - **Port**
     - Exact integer match against ``srcPort`` **or** ``dstPort``. Digits only.
   * - **Payload contains**
     - Searches the stored 64-byte payload hex of every packet in the
       conversation. Accepts: plain ASCII string (e.g. ``GET /admin``), hex
       with ``0x`` prefix (e.g. ``0x474554``), or space-separated hex bytes
       (e.g. ``47 45 54``).
   * - **Security risks only**
     - Toggle: shows only conversations that have at least one nDPI risk flag
       (the ``flowRisks`` array is non-empty).
   * - **IDS Alerts** (searchable)
     - Suricata signature matches. Select one or more alert names to show only
       conversations that triggered them. Values are populated from the distinct
       alerts present in the current file. See :doc:`ids-threat-detection`.
   * - **Protocol** (pills)
     - The ``_ws.col.Protocol`` label — Wireshark's display column, representing
       the highest protocol layer its dissectors identified for each packet
       (e.g. TCP, UDP, TLS, HTTP, DNS). Note: filtering for ``TCP`` here will
       exclude packets Wireshark dissected further to ``HTTP`` or ``TLS``.
       Multiple selections are OR-matched.
   * - **Dissected Protocol** (pills)
     - The ``tsharkProtocol`` — deepest protocol Wireshark's dissectors decoded
       from the ``frame.protocols`` stack (e.g. TLS, HTTP, DNS, QUIC).
       Multiple selections are OR-matched.
   * - **Application** (pills)
     - The nDPI ``appName`` — application or service identified by deep packet
       inspection (e.g. YouTube, WhatsApp). Detection accuracy may vary; treat
       as indicative. Only present when nDPI analysis was enabled.
   * - **Category** (pills)
     - The nDPI traffic category (e.g. Web, Media, VPN, Social Network).
       Multiple selections are OR-matched.
   * - **File Types** (pills)
     - Shows only conversations containing at least one packet where a file
       magic-byte signature was detected in the stored 64-byte payload
       (e.g. PDF, ZIP, PNG).
   * - **Risk Type** (pills)
     - Individual nDPI risk flag names (e.g. ``clear_text_credentials``,
       ``tls_self_signed_certificate``). Multiple selections are OR-matched.
   * - **Custom Rules** (pills)
     - Custom detection rule names from ``signatures.yml`` that fired in this
       PCAP. Only rules that matched at least one conversation are shown.
       Severity quick-select buttons (critical/high/medium/low) select all
       rules of that severity level at once.
   * - **Country** (pills)
     - Country of external IP addresses (src or dst) from ipinfo.io (online)
       or DB-IP Lite (offline). Multiple selections are OR-matched.
   * - **Device Type** (pills)
     - Predicted device class (Router, Mobile, etc.) for either the source or
       destination IP. Based on the multi-signal classifier; custom signature
       overrides apply at 100% confidence.

Sorting
-------

Click any column header to sort ascending; click again for descending.
Multi-column sorting is supported — hold **Shift** and click a second column.

Pagination
----------

Results are paginated. The page size is configurable from 10 to 100 rows.

Conversation Detail Panel
--------------------------

Clicking a row opens the **Conversation Detail Panel**, which shows all
fields for a single conversation in one place. The fields displayed depend on
what data was available during analysis:

**Identity and endpoints**

- Source IP : Port and Destination IP : Port
- Destination hostname (SNI from TLS ClientHello, if available)
- **Device type badges** — shown next to each IP if the device classifier ran.
  Clicking the badge opens the **Device Classification Popup** (see below).
- **Country / ASN** — for external IPs; includes a clickable geo-source badge:

  - **ipinfo.io** (green badge) — looked up via the ipinfo.io API. Provides
    country, region, city, ASN, and organisation. Results are cached locally
    so the API is not called again for known IPs.
  - **Offline DB** (grey badge) — resolved from the bundled DB-IP Lite MMDB.
    Used when the app is offline or ipinfo.io is unreachable. Accuracy may be
    lower, especially for cloud-provider IP ranges. ASN is not available from
    this source.

**Protocol fields**

- **Protocol** — ``_ws.col.Protocol`` label (Wireshark display column).
- **Dissected Protocol** — ``tsharkProtocol`` from the deepest
  ``frame.protocols`` stack layer (see `Protocol vs Application`_).
- **Application** — nDPI ``appName`` (may be absent if nDPI was not enabled).

**Security fields**

- **Security Flags** — nDPI risk flags (e.g. ``tls_self_signed_certificate``,
  ``clear_text_credentials``). These are stored as normalized
  ``lowercase_underscore`` strings from nDPI's ``[Risk: ...]`` output.
- **Custom Rules** — names of fired custom signature rules, color-coded by
  severity (critical=red, high=orange, medium=amber, low=purple).

**TLS metadata** (when nDPI analysis was enabled and a TLS handshake was
observed)

- **JA3 Client** — MD5 hash of the TLS ClientHello parameters.
- **JA3S Server** — MD5 hash of the TLS ServerHello parameters.
- **TLS Issuer** — Issuer DN from the server certificate.
- **TLS Subject** — Subject DN from the server certificate.
- **Cert Valid From / Cert Valid To** — certificate validity dates from
  ``NotBefore`` / ``NotAfter`` fields. The "Valid To" date is highlighted in
  red and an **Expired** badge is shown if ``NotAfter < now`` at the time
  the page is viewed.

**HTTP metadata**

- **User-Agents** — distinct ``http.user_agent`` values extracted during the
  tshark enrichment pass, shown as a list.

**Statistics**

- Packet count, total bytes, start time.

**Packet table**

The lower section shows the individual stored packets for the conversation.
Each row has:

- Packet index (1-based within this conversation)
- Direction arrow (→ blue = client-to-server, ← green = server-to-client;
  direction is relative to the conversation's ``srcIp``)
- Timestamp from the PCAP frame
- Source IP:Port / Destination IP:Port
- Frame length (``frame.len``) in bytes — includes all headers
- **File Type** — if a magic-byte signature was detected in the first 64 bytes
  of the stored payload hex, the detected file type is shown as a badge
  (e.g. ``PDF``, ``ZIP``, ``PNG``). An **ASCII** badge appears if > 30% of
  the first 256 payload bytes are printable ASCII characters.
- Info — the ``_ws.col.Info`` tshark display column for the packet

Click a packet row to expand the **Hex Viewer**, which renders the stored
64-byte payload as both hex and ASCII side-by-side.

**Extracted files link**

If File Extraction was enabled at upload time and files were extracted from
this conversation's stream, a button shows the count and links to the
Extracted Files tab filtered to this conversation.

Device Classification Popup (Conversation Detail)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The device type badge next to each IP in the Conversation Detail Panel opens
a simplified classification popup scoped to this specific conversation:

- **Type** — whether this IP acted as ``Client`` (initiated) or ``Server``
  (received) in this conversation. For server-role IPs, the label uses a
  port-to-service mapping on the destination port (e.g. port 443 → ``HTTPS``).
  The note below explains: "Based on destination port N in this conversation".
- **Device** — same device type badge, signal bullets, and confidence progress
  bar as the Network Visualization popup (see :doc:`network-visualization`).
- **Role** — ``Client`` or ``Server`` badge with a one-line note.

This popup is distinct from the Network Visualization Classification popup in
that it is conversation-scoped rather than global (it does not show initiated/
received counts across all conversations).

Conversation Tracer
-------------------

The **Conversation Tracer** is opened from the conversation list via the tracer
icon. It provides a step-by-step replay of every packet in the conversation,
with an LLM-generated plain-English explanation for each packet.

Star-Graph Visualization
~~~~~~~~~~~~~~~~~~~~~~~~~

A star-graph SVG shows the traced host (center node, labelled "Host") and up
to 12 of its peer IPs arranged in a ring. Each peer is drawn in one of three
states so that scan patterns are visible at a glance:

- **Responded** (green / solid edge) — the peer sent at least one packet back
  to the host.
- **No response** (dimmed / dashed edge) — the host probed the peer but nothing
  came back. A ring of these around one host is the signature of a scan (e.g.
  an ARP or port sweep).
- **Currently traced** (blue) — the peer whose packets are being replayed.

A legend beneath the graph shows the counts of responded vs silent peers. The
responded flag for each peer comes from a dedicated endpoint
(``GET /api/v1/tracer/{conversationId}/peers``) that reports, per peer, whether
any reply from that peer to the host exists in the capture.

An animated dot travels along the active edge on each step advance:

- **Blue dot** (→) — packet travelling client-to-server.
- **Green dot** (←) — packet travelling server-to-client.

Direction is determined relative to the conversation's stored ``srcIp``:
packets where ``packet.srcIp == conversation.srcIp`` are labelled ``CLIENT``
(outbound), others are ``SERVER`` (inbound).

Below the graph, a step summary line shows: direction arrow, protocol,
size in bytes, and a truncated version of the ``_ws.col.Info`` string for
the current packet.

LLM Packet Explanations
~~~~~~~~~~~~~~~~~~~~~~~~

For each packet, the LLM receives:

- Direction (``CLIENT->SERVER`` or ``SERVER->CLIENT``)
- Protocol (``_ws.col.Protocol`` label)
- Packet size in bytes
- Info string (``_ws.col.Info``) where present
- Up to 64 bytes of payload rendered as ASCII, with non-printable bytes
  replaced by ``.``. Only included if the payload contains at least 4
  consecutive printable ASCII characters. Encrypted payloads produce no
  readable ASCII and are excluded.

The LLM is asked to produce a 1-2 sentence plain-English explanation of what
is happening at that network step, in the context of the full conversation
(protocol, application name, endpoint IPs/ports).

The system caches LLM explanations per conversation (up to 500 entries in an
LRU cache), so switching steps or reopening the tracer does not make repeated
LLM calls.

**Works well for:** TCP handshakes, HTTP requests/responses, DNS queries, TLS
handshake phases — where the Info field or payload bytes are descriptive.

**Limited for:** encrypted traffic (TLS application data, RDP) where only
size and direction are available — explanations will be generic.

Packet List
~~~~~~~~~~~

The scrollable packet list below the controls shows all packets with: step
index, direction, protocol, size, timestamp (time component only), and
truncated Info string. Clicking any row jumps directly to that step.

Navigation controls: Previous / Next buttons, current step / total counter,
and a Play/Pause button that auto-advances at 1.5-second intervals.

Session Reconstruction
-----------------------

Click the **eye icon** on any row to open the session reconstruction viewer
for that conversation — see :doc:`session-reconstruction`.

Export Options
--------------

- **Per-conversation PCAP** — download a PCAP containing only the packets
  for a single conversation via the row action menu.
- **Bulk PCAP export** — select multiple rows (or all) and export them as
  a combined PCAP.
- **CSV export** — export the current filtered and sorted view to CSV.
