MAC Manufacturer Lookup
========================

TracePcap integrates the **Wireshark OUI (Organizationally Unique Identifier)
database** to resolve MAC address prefixes to vendor names.

How It Works
------------

The first three octets of a MAC address identify the manufacturer (e.g.
``00:50:56`` → VMware, ``b8:27:eb`` → Raspberry Pi Foundation). TracePcap
looks up these prefixes against the bundled Wireshark OUI database, which
is updated periodically and included in the Docker image — no internet
connection is needed.

Where Vendor Names Appear
--------------------------

- **Network Visualization** — shown in the Node Detail Panel when you click
  a host node.
- **Conversations** — a ``Vendor`` column (hidden by default; enable via
  Column Picker).
- **Overview** — top vendors by conversation count.

Limitations
-----------

- MAC addresses are only visible for hosts on the **same Layer-2 segment**
  as the capture point. Hosts routed across layer-3 boundaries will not have
  a MAC address visible in the PCAP.
- Locally-administered MAC addresses (randomised by modern OSes) cannot be
  resolved to a meaningful vendor.
- Virtual MAC addresses (VMware, VirtualBox, Docker bridge) resolve to the
  hypervisor vendor, not the guest OS.
