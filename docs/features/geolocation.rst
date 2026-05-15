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
**multi-signal scoring system**. Four signal types contribute weighted scores;
the type with the highest total score wins:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Signal
     - How it works
   * - **MAC OUI lookup**
     - The first 3 octets of the MAC address are resolved against the bundled
       Wireshark ``manuf`` file. Vendor names are matched against a fixed
       table — e.g. Apple/Samsung/Google → ``MOBILE``; Cisco/Netgear/Ubiquiti
       → ``ROUTER``; Dell/Lenovo/Intel → ``LAPTOP_DESKTOP``;
       Raspberry Pi/Espressif → ``IOT``. A match adds **+40 points**.
   * - **TTL fingerprinting**
     - The observed IP TTL is normalized to the nearest standard initial value.
       TTL ~128 (Windows) → ``LAPTOP_DESKTOP`` (+30). TTL ~64 (Linux/Android)
       → ``SERVER``, ``MOBILE``, ``ROUTER`` (+10 each). TTL ~255
       (Cisco/network gear) → ``ROUTER`` (+30).
   * - **nDPI app profile**
     - Applications seen in conversations are matched against configurable
       sets of mobile apps, desktop apps, server apps, and IoT categories.
       Each matching app adds **+20 points** to the relevant type.
   * - **Traffic patterns**
     - ≥15 distinct peers → ``ROUTER`` (+35). Never initiates + receives on
       well-known ports (<1024) → ``SERVER`` (+35). ≤2 apps, ≤5 conversations,
       <200 packets → ``IOT`` (+20). >70% initiated traffic + >3 distinct apps
       → ``MOBILE``/``LAPTOP_DESKTOP`` (+10). Only DNS/NTP traffic →
       ``ROUTER``/``SERVER`` (+20/+15).

**Confidence** is derived from the score margin between the winning type and
the runner-up: a margin of ≥60 points → 100%; scaled linearly to 0% at a
margin of 0.

A ``device_type`` field in a custom signature rule **overrides** all
heuristics with confidence 100 — see :doc:`custom-signatures`.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Device Type
     - Typical signals
   * - ``ROUTER``
     - High peer count, TTL ~255, Cisco/Netgear OUI, DNS/NTP-only traffic
   * - ``SERVER``
     - Never initiates, receives on well-known ports (<1024)
   * - ``IOT``
     - Low app variety, low packet count, Raspberry Pi / Espressif OUI
   * - ``MOBILE``
     - Apple/Samsung OUI, mobile nDPI apps (Telegram, WhatsApp, etc.)
   * - ``LAPTOP_DESKTOP``
     - TTL ~128 (Windows), Dell/Lenovo OUI, browser-associated apps
   * - ``UNKNOWN``
     - Insufficient signals to classify

Device types are displayed as icons in the Network Visualization and as a
filterable column in Conversations.
