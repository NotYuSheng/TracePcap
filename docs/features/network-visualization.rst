Network Visualization
=====================

The Network Visualization tab renders an interactive topology graph of all
hosts and flows extracted from the PCAP file.

Technology
----------

The graph is built with **React Flow** and laid out using the **ELK** (Eclipse
Layout Kernel) automatic layout engine. No external tile servers or map
services are used — the topology is a pure data-driven graph rendered in the
browser.

Nodes
-----

Each node represents a unique IP address (or MAC address for layer-2 traffic).
Node appearance reflects:

- **Device type** — icon and shape vary by predicted device class
  (Router, Server, IoT, Mobile, Laptop/Desktop).
- **Country** — a flag badge on external (non-RFC-1918) IPs.
- **Risk** — nodes involved in risky conversations display a warning indicator.

Click a node to open the **Node Detail Panel**, which shows:

- IP address and MAC address
- Vendor (from Wireshark OUI database)
- Predicted device type
- Country and ASN (for external IPs)
- List of conversations involving this node

Edges
-----

Edges represent observed conversations between two hosts. Edge thickness
reflects relative traffic volume.

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

Layout Controls
---------------

- **Auto layout** — re-run ELK layout.
- **Fullscreen toggle** — expand the graph to fill the viewport.
- **Zoom controls** — zoom in/out and fit-to-screen buttons.

Export
------

The topology can be captured as part of the PDF report via the **Export PDF**
button (see :doc:`../operations/backup-restore`).
