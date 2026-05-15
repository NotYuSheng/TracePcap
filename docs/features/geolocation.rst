Geolocation & Device Classification
=====================================

Geolocation
-----------

TracePcap enriches every external (non-RFC-1918) IP address with country and
ASN (Autonomous System Number) information.

The geolocation database is bundled inside the Docker image — no internet
connection is required at runtime.

Data Shown
~~~~~~~~~~

- **Country** — ISO 3166-1 alpha-2 code and flag displayed inline.
- **ASN** — Autonomous System number and organisation name.

These fields appear in:

- The **Conversations** tab (src country, dst country columns).
- The **Network Visualization** — flag badge on external host nodes.
- The **Node Detail Panel**.
- The **Overview** tab — top countries by conversation count.

Private / Reserved IPs
~~~~~~~~~~~~~~~~~~~~~~~

RFC-1918 addresses (``10.x.x.x``, ``172.16-31.x.x``, ``192.168.x.x``),
loopback, link-local, and other reserved ranges are labelled **Private** and
are not looked up in the geolocation database.

Device Classification
---------------------

TracePcap predicts the **device type** of each observed IP address based on
heuristics applied to traffic patterns, port behaviour, and protocol mix:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Device Type
     - Heuristic signals
   * - **Router**
     - Observed forwarding traffic, TTL patterns, routing protocols
   * - **Server**
     - Mostly inbound connections, well-known server ports (80, 443, 22, …)
   * - **IoT**
     - Low-entropy traffic, known IoT protocol ports (MQTT, CoAP, …)
   * - **Mobile**
     - Mobile-specific app protocols, IMSI/IMEI patterns
   * - **Laptop/Desktop**
     - Mixed client traffic, browser fingerprints

Device types are displayed as icons in the Network Visualization and as a
filterable column in Conversations.

Custom Signature Override
~~~~~~~~~~~~~~~~~~~~~~~~~

Custom signature rules can pin an IP to a specific device type via the
``device_type`` field — see :doc:`custom-signatures` for details.
