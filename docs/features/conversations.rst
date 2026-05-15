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
     -e frame.time_epoch   \  # Unix epoch with sub-second precision
     -e frame.len          \  # total on-wire frame length in bytes
     -e ip.src             \  # IPv4 source address (empty for IPv6-only)
     -e ip.dst             \  # IPv4 destination address
     -e ipv6.src           \  # IPv6 source (fallback when IPv4 is absent)
     -e ipv6.dst           \  # IPv6 destination
     -e tcp.srcport        \  # TCP source port (empty for non-TCP)
     -e tcp.dstport        \
     -e udp.srcport        \  # UDP source port (empty for non-UDP)
     -e udp.dstport        \
     -e _ws.col.Protocol   \  # Wireshark's "Protocol" display column label
     -e _ws.col.Info       \  # Wireshark's "Info" display column
     -e tcp.payload        \  # raw TCP payload bytes (colon-hex, e.g. 48:54:54:50)
     -e udp.payload        \
     -e ip.ttl             \  # IP time-to-live field
     -e eth.src            \  # Ethernet source MAC address
     -e arp.src.proto_ipv4 \  # ARP sender IP (for ARP frames)
     -e arp.dst.proto_ipv4 \  # ARP target IP
     -e eth.dst               # Ethernet destination MAC

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
2. If ``srcIp < dstIp``: the canonical form is ``srcIp:srcPort–dstIp:dstPort``.
3. If ``srcIp > dstIp``: swap, so the canonical form is ``dstIp:dstPort–srcIp:srcPort``.
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
- Country (src / dst) — from ipinfo.io or DB-IP MMDB lookup
- Device type (src / dst) — from the multi-signal device classifier
- Bytes transferred — sum of ``frame.len`` for all matched packets
- Packet count — number of matched frames (both directions)
- Start / end timestamp — from PCAP frame timestamps
- Custom signature matches — names of fired custom detection rules
- HTTP User-Agent — extracted from ``http.user_agent`` tshark field

Filtering
---------

The filter bar supports simultaneous filtering on:

- IP address (src, dst, or either)
- Port (src, dst, or either)
- Protocol (TCP, UDP, ICMP, …)
- Application name (nDPI)
- Risk level
- Custom signature rule name
- Device type
- Country
- Payload pattern (substring search across reconstructed payloads)

Multiple filters combine with AND logic.

Sorting
-------

Click any column header to sort ascending; click again for descending.
Multi-column sorting is supported — hold **Shift** and click a second column.

Pagination
----------

Results are paginated. The page size is configurable from 10 to 100 rows.

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
