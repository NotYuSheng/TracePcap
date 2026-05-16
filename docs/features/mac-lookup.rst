MAC Manufacturer Lookup
========================

TracePcap integrates the **Wireshark OUI (Organizationally Unique Identifier)
database** to resolve MAC address prefixes to vendor names.

How MAC Addresses Are Captured
-------------------------------

During the tshark parsing pass, the field ``eth.src`` (Ethernet source MAC
address) is extracted for every packet. TracePcap records the **first-seen**
``eth.src`` value for each source IP address encountered in the PCAP. This
means:

- A host's MAC address entry is set the first time a packet from that IP
  appears in the capture — subsequent packets from the same IP (even if the
  MAC changes, e.g. due to MAC rotation) do not update the stored value.
- Only **source** MAC addresses are stored per source IP. If a host only
  appears as a destination in the PCAP (i.e., all packets are inbound, no
  outbound replies were captured), the host will have no MAC address entry.
- MAC addresses are always stored in lowercase, colon-separated format
  (e.g. ``b8:27:eb:1c:4a:2f``).

How the OUI Lookup Works
-------------------------

The first three octets of a MAC address (the OUI prefix) identify the
manufacturer. For example:

- ``00:50:56`` → VMware
- ``b8:27:eb`` → Raspberry Pi Foundation
- ``3c:22:fb`` → Apple

TracePcap looks up these prefixes against the **bundled Wireshark ``manuf``
database**, which is included in the Docker image. No internet connection is
needed. The same database is used by the **device classifier** (see
:doc:`geolocation`) to assign OUI-based device type scores.

A match returns the vendor's short name. The OUI database contains tens of
thousands of registered prefixes but does not cover all possible OUIs —
unregistered or vendor-private prefixes return no vendor name.

Where Vendor Names Appear
--------------------------

- **Network Visualization** — shown in the Node Detail Panel when you click
  a host node.
- **Conversations** — a ``Vendor`` column (hidden by default; enable via
  Column Picker).
- **Overview** — top vendors by conversation count.

Limitations
-----------

**Layer-2 adjacency requirement**

MAC addresses are only visible for hosts on the **same Layer-2 broadcast
domain** as the capture point. When traffic passes through a router,
the router rewrites the Ethernet source/destination MAC addresses. This means:

- Hosts on the same LAN segment as the capturing host: MAC visible.
- Hosts on a remote subnet (traffic routed via a gateway): the PCAP will show
  the **gateway's MAC address** as the source, not the actual remote host's MAC.
  The vendor name will therefore be the router vendor (e.g. Cisco, Ubiquiti),
  not the end-host vendor.
- Internet hosts: MAC address is always the last-hop router/firewall, not
  the remote server.

**Locally-administered (randomised) MAC addresses**

Modern operating systems (Android 10+, iOS 14+, Windows 10+) randomise
MAC addresses for Wi-Fi associations. These randomised addresses have the
second-least-significant bit of the first octet set to 1 (e.g. ``da:``
instead of ``d8:``). Randomised addresses are not registered in the OUI
database and will return no vendor name.

**Virtual adapters**

Virtual MAC addresses (VMware VMXNET, VirtualBox, Docker bridge, Hyper-V)
resolve to the **hypervisor vendor** (e.g. ``00:0c:29`` → VMware), not the
guest operating system. The vendor name reflects the virtualisation platform,
not the actual application running inside the VM.

**MAC addresses as node identifiers for non-IP traffic**

For non-IP Layer-2 frames (STP, LLDP, CDP, EAP, etc.) where no IP address
is available, TracePcap uses the Ethernet MAC address as the node identifier
in the Network Visualization. In this case the "IP" field in the UI will
display a MAC address, and the OUI lookup will apply normally to derive the
vendor name.
