Geolocation & Device Classification
=====================================

Geolocation
-----------

TracePcap enriches every external (non-RFC-1918) IP address with country and
ASN information using a two-source lookup strategy:

1. **ipinfo.io** (online) — queried first when internet is reachable.
   Returns country, region, city, ASN, and organisation name. The ``org``
   field (e.g. ``AS8075 Microsoft Corporation``) is split into the ASN number
   and organisation name. Results are cached permanently in PostgreSQL.
2. **DB-IP Lite MMDB** (offline fallback) — bundled inside the Docker image.
   Used automatically when internet is unreachable or ipinfo.io fails.
   Returns country, region, and city. ASN data is not available from the
   MMDB source.

The source used for each cached entry (``"ipinfo"`` or ``"mmdb"``) is stored
and can be surfaced in the UI so users understand the data accuracy context.
On an air-gapped machine the MMDB is used exclusively.

Cached entries older than **30 days** are treated as stale and re-looked up
on the next analysis run.

Data Shown
~~~~~~~~~~

- **Country** — ISO 3166-1 alpha-2 code and flag displayed inline.
- **Region / City** — state/province and city name (where available).
- **ASN** — Autonomous System number and organisation name (ipinfo.io only).

These fields appear in:

- The **Conversations** tab (src country, dst country columns).
- The **Network Visualization** — flag badge on external host nodes.
- The **Node Detail Panel**.
- The **Overview** tab — top countries by conversation count.

Private / Reserved IPs
~~~~~~~~~~~~~~~~~~~~~~~

RFC-1918 addresses (``10.x.x.x``, ``172.16–31.x.x``, ``192.168.x.x``),
loopback (``127.x.x.x``), link-local (``169.254.x.x``), IPv6 loopback
(``::1``), ULA (``fc::/7``), and link-local (``fe80::/10``) are classified
as **Private** and are not looked up.

Device Classification
---------------------

TracePcap classifies each unique IP address into a device type using a
**multi-signal scoring system**. Four signal types contribute weighted scores
to five possible device type buckets; the type with the highest total score
wins. If all scores are zero, the result is ``UNKNOWN``.

Host Profile Construction
~~~~~~~~~~~~~~~~~~~~~~~~~~

Before scoring, a profile is built for each IP by iterating over all
conversations in the PCAP. For each conversation, the IP is encountered either
as the source (initiator) or as the destination (receiver):

- **Initiator**: ``initiatedCount`` is incremented; the destination port is
  added to ``dstPorts``; the peer IP is added to the ``peers`` set.
- **Receiver**: the destination port is added to ``receivedOnPorts``; the peer
  IP is added to the ``peers`` set.
- For both roles: the nDPI ``appName`` is added to ``apps``; the nDPI
  ``category`` is added to ``categories``; ``conversationCount`` is
  incremented; ``totalBytes`` and ``totalPackets`` accumulate.

Signal 1: MAC OUI Lookup (+40 points)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The first 3 octets of the source MAC address (recorded during tshark parsing
as ``eth.src``) are resolved against the Wireshark ``manuf`` database to get
the vendor short name. The vendor name is then matched (case-insensitive
substring) against a fixed table:

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - Vendor substring
     - Device type
     - Examples
   * - ``apple``
     - ``MOBILE``
     - Apple iPhones, iPads, MacBooks (note: Apple OUIs span many device types)
   * - ``samsung``
     - ``MOBILE``
     - Samsung smartphones
   * - ``google``
     - ``MOBILE``
     - Google Pixel phones, Nest devices
   * - ``oneplus``, ``xiaomi``
     - ``MOBILE``
     - Android phone manufacturers
   * - ``cisco``
     - ``ROUTER``
     - Cisco routers and switches
   * - ``huawei``, ``tp-link``, ``tplink``, ``netgear``, ``asus``, ``ubiquiti``, ``mikrotik``
     - ``ROUTER``
     - Common consumer/enterprise networking gear
   * - ``dell``, ``intel``, ``lenovo``, ``hewlett packard``, ``hp inc``, ``acer``
     - ``LAPTOP_DESKTOP``
     - PC hardware vendors
   * - ``raspberry pi``, ``espressif``, ``arduino``
     - ``IOT``
     - Common IoT hardware platforms

Only the first matching vendor substring wins — the table is checked in order.
If the vendor name does not match any entry, no OUI score is added.

The MAC address is only available if the host is on the same Layer-2 segment
as the capture point. See :doc:`mac-lookup` for the full scope limitation.

Signal 2: TTL Fingerprinting (up to +30 points)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every IP packet carries a ``Time To Live`` (TTL) field that the sending OS
initialises to a standard value, then each router hop decrements by 1. By
examining the **observed** TTL in the PCAP (from the ``ip.ttl`` tshark field)
we can infer the **initial** TTL and thereby the likely OS family.

TTL normalisation: the observed TTL is rounded up to the nearest standard
initial value:

- Observed TTL > 128 → initial TTL assumed to be **255** (Cisco IOS, network
  devices)
- Observed TTL > 64 → initial TTL assumed to be **128** (Windows)
- Observed TTL ≤ 64 → initial TTL assumed to be **64** (Linux, macOS, Android,
  iOS, most Unix-like systems)

Scoring based on the normalised initial TTL:

- ``255`` → ``ROUTER`` **+30**
- ``128`` → ``LAPTOP_DESKTOP`` **+30**
- ``64`` → ``SERVER`` **+10**, ``MOBILE`` **+10**, ``ROUTER`` **+10**
  (three types share the same initial TTL, so all receive a small boost;
  other signals must disambiguate)

The TTL used is the **first-seen** TTL from the first packet where that IP
appeared as source. Only one TTL value is stored per IP.

Signal 3: nDPI App Profile (up to +20 points per matching app)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The set of nDPI ``appName`` values observed for an IP (across all its
conversations) is matched against configurable app lists:

- Each app in the **mobile apps** list → ``MOBILE`` **+20**
- Each app in the **desktop apps** list → ``LAPTOP_DESKTOP`` **+20**
- Each app in the **server apps** list → ``SERVER`` **+20**
- Each nDPI **category** in the IoT categories list → ``IOT`` **+15**
- nDPI category ``Web`` or ``Media`` → ``LAPTOP_DESKTOP`` **+5**

This signal scales with the number of distinct matching apps — a host that
generates Telegram, WhatsApp, and Instagram traffic accumulates three
``MOBILE`` boosts (+60 total from this signal alone).

Signal 4: Traffic Patterns (up to +35 points)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Heuristics applied to the host profile:

**High peer count → ROUTER**

- ≥ 15 distinct peer IPs → ``ROUTER`` **+35**
- ≥ 8 distinct peer IPs → ``ROUTER`` **+15**

**Receives on well-known ports without initiating → SERVER**

- Never initiated any conversation AND received on at least one port < 1024
  → ``SERVER`` **+35**
- Never initiated any conversation (but no port evidence) → ``SERVER`` **+15**

**Low variety and volume → IOT**

- ≤ 2 distinct nDPI apps AND ≤ 5 conversations AND < 200 total packets
  → ``IOT`` **+20**

**Client-like traffic pattern → MOBILE / LAPTOP_DESKTOP**

- Initiated > 70% of conversations AND observed > 3 distinct nDPI apps
  → ``MOBILE`` **+10** AND ``LAPTOP_DESKTOP`` **+10**

**Only infrastructure traffic → ROUTER / SERVER**

- All nDPI apps are ``DNS`` or ``NTP`` (and at least one is present)
  → ``ROUTER`` **+20**, ``SERVER`` **+15**

Confidence Calculation
~~~~~~~~~~~~~~~~~~~~~~

After all four signals have been scored, confidence is calculated from the
**margin** between the winning score and the second-highest score:

.. code-block:: text

   confidence = min(100, round( margin × 100 / 60 ))

Where ``margin = best_score − second_best_score``.

- Margin ≥ 60 → 100% confidence
- Margin of 0 (two types tied) → 0% confidence
- Intermediate margins scale linearly: a margin of 30 = 50% confidence

A high confidence value means the classification is unambiguous (one device
type dominates). A low confidence value means multiple device types received
similar scores and the result should be treated as a best guess.

.. note::
   The raw signal weights (e.g. +40 for OUI, +30 for TTL) do **not** map
   directly to a confidence percentage. A device that accumulates a large
   total score is not necessarily high-confidence — it depends on how
   far ahead it is of the runner-up type. The same +40 OUI signal raises
   confidence a lot if other signals are silent, but less so if those same
   +40 points also raise a competing type.

Worked Examples
^^^^^^^^^^^^^^^

**Example 1 — High confidence Router**

A host has a Cisco OUI, TTL 255, 20 distinct peers, and only DNS/NTP traffic.

.. list-table::
   :header-rows: 1
   :widths: 20 15 15 15 15 15

   * - Signal
     - ROUTER
     - SERVER
     - MOBILE
     - LAPTOP
     - IOT
   * - OUI (Cisco → ROUTER +40)
     - +40
     - —
     - —
     - —
     - —
   * - TTL 255 → ROUTER +30
     - +30
     - —
     - —
     - —
     - —
   * - 20 peers → ROUTER +35
     - +35
     - —
     - —
     - —
     - —
   * - DNS/NTP only → ROUTER +20, SERVER +15
     - +20
     - +15
     - —
     - —
     - —
   * - **Total**
     - **125**
     - **15**
     - **0**
     - **0**
     - **0**

Margin = 125 − 15 = **110** → capped at 60 → **confidence 100%**

**Example 2 — Low confidence IoT (your TTL-64 case)**

A host has no MAC OUI resolved, TTL 64, 1 observed app (unmatched category),
and only 3 conversations with low packet count — triggering the IoT
low-variety heuristic.

.. list-table::
   :header-rows: 1
   :widths: 20 15 15 15 15 15

   * - Signal
     - ROUTER
     - SERVER
     - MOBILE
     - LAPTOP
     - IOT
   * - OUI — not resolved
     - —
     - —
     - —
     - —
     - —
   * - TTL 64 → +10 each to SERVER, MOBILE, ROUTER
     - +10
     - +10
     - +10
     - —
     - —
   * - Low variety (≤2 apps, ≤5 convs, <200 pkts) → IOT +20
     - —
     - —
     - —
     - —
     - +20
   * - **Total**
     - **10**
     - **10**
     - **10**
     - **0**
     - **20**

Margin = 20 − 10 = **10** → ``round(10 × 100 / 60)`` = **17% confidence**

IOT wins, but three other types are only 10 points behind. The classification
is a best guess — resolving the MAC OUI would either confirm or overturn it.

**Example 3 — Moderate confidence Laptop/Desktop**

A host has a Dell OUI, TTL 128, Zoom and Teams traffic, and a client-like
initiation ratio.

.. list-table::
   :header-rows: 1
   :widths: 20 15 15 15 15 15

   * - Signal
     - ROUTER
     - SERVER
     - MOBILE
     - LAPTOP
     - IOT
   * - OUI (Dell → LAPTOP +40)
     - —
     - —
     - —
     - +40
     - —
   * - TTL 128 → LAPTOP +30
     - —
     - —
     - —
     - +30
     - —
   * - Zoom → LAPTOP +20, Teams → LAPTOP +20
     - —
     - —
     - —
     - +40
     - —
   * - >70% outbound, >3 apps → MOBILE +10, LAPTOP +10
     - —
     - —
     - +10
     - +10
     - —
   * - **Total**
     - **0**
     - **0**
     - **10**
     - **120**
     - **0**

Margin = 120 − 10 = **110** → capped at 60 → **confidence 100%**

**Example 4 — Ambiguous Mobile vs Laptop**

A host with an Apple OUI (Apple spans iPhones and MacBooks), TTL 64, and no
distinguishing app traffic.

.. list-table::
   :header-rows: 1
   :widths: 20 15 15 15 15 15

   * - Signal
     - ROUTER
     - SERVER
     - MOBILE
     - LAPTOP
     - IOT
   * - OUI (Apple → MOBILE +40)
     - —
     - —
     - +40
     - —
     - —
   * - TTL 64 → +10 each to SERVER, MOBILE, ROUTER
     - +10
     - +10
     - +10
     - —
     - —
   * - No app signals
     - —
     - —
     - —
     - —
     - —
   * - **Total**
     - **10**
     - **10**
     - **50**
     - **0**
     - **0**

Margin = 50 − 10 = **40** → ``round(40 × 100 / 60)`` = **67% confidence**

MOBILE wins, but confidence is not 100% because Apple OUIs cover both iPhones
and MacBooks. Observing mobile-specific apps (e.g. WhatsApp, Instagram) would
push the margin to ≥ 60 and confidence to 100%.

Custom Signature Override
~~~~~~~~~~~~~~~~~~~~~~~~~

A ``device_type`` field in a custom signature rule **overrides** all
heuristics with confidence **100** for every IP address involved in a matching
conversation — see :doc:`custom-signatures`. Standard values (``ROUTER``,
``MOBILE``, ``LAPTOP_DESKTOP``, ``SERVER``, ``IOT``, ``UNKNOWN``) and custom
strings (e.g. ``"PLC"``, ``"CCTV Camera"``) are both accepted.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Device Type
     - Typical winning signals
   * - ``ROUTER``
     - High peer count (≥15), TTL ~255, Cisco/Netgear/Ubiquiti OUI, DNS/NTP-only apps
   * - ``SERVER``
     - Never initiates, receives on well-known ports (<1024), server app profile
   * - ``IOT``
     - Low app variety (≤2), low conversation count (≤5), Raspberry Pi/Espressif OUI
   * - ``MOBILE``
     - Apple/Samsung/Google OUI, mobile app profile (Telegram, WhatsApp, Instagram, etc.)
   * - ``LAPTOP_DESKTOP``
     - TTL ~128 (Windows), Dell/Lenovo/Intel OUI, browser/desktop app profile
   * - ``UNKNOWN``
     - All signals scored zero — insufficient data to classify

Device types are displayed as icons in the Network Visualization and as a
filterable column in Conversations. The confidence score is shown in the Node
Detail Panel.
