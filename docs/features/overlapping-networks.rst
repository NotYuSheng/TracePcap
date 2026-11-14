Networks Sharing a Range
========================

Two networks can use the same addresses: two sites both on ``192.168.1.0/24``,
or two VLANs with the same range. A capture from a trunk port, or two sites'
captures merged into one, then holds both. ``192.168.1.10`` at one site is a
different machine from ``192.168.1.10`` at the other, but by address alone they
look like one host.

TracePcap tells such networks apart from their **DHCP leases**, and shows them
on the capture's **Overview** when it finds more than one on a range.

How Networks Are Told Apart
---------------------------

Each DHCP server names itself and the network in the lease it hands out. For
every lease, TracePcap keeps:

- the **802.1Q VLAN** the server's reply was tagged with, when the capture has
  VLAN tags;
- the **DHCP server's MAC**: two sites' routers can both be ``192.168.1.1`` but
  have different MACs;
- the server identifier, router, **domain** (for example ``hq.corp.example``),
  lease time and subnet mask it gave.

Leases are grouped into one network per VLAN, or, with no VLAN tags, per DHCP
server MAC. Two networks whose ranges overlap are shown together.

What It Shows
-------------

**N networks share 192.168.1.0/24**, with a card per network:

- its VLAN, router, DHCP server MAC, domain and lease time;
- the clients it leased addresses to (address, hostname, MAC).

Then the **addresses used on more than one** of them, including the routers'
when they share one. Each is a different machine on each network.

On those addresses:

- The host's details warn **Used on 2 networks that share this range (…): a
  different machine on each.**
- They aren't split into devices over time (see :doc:`address-reuse`). Two
  networks at once aren't one device handing an address to another.

What This Doesn't Change Yet
----------------------------

Outside the Overview panel and that warning, an address used on two networks is
still **one host**: one classification, one graph node, and one set of labels,
mixing both machines. Keeping them apart everywhere, with the network as part of
a host's identity, is planned (#462).

Only addresses that got a DHCP lease (and the routers) can be placed on a
network. A static address with no lease isn't assigned to either.

Try It
------

``sample-files/two_sites_overlap.pcap`` has two sites, HQ (VLAN 10) and Branch
(VLAN 20), both on ``192.168.1.0/24`` with a router at ``192.168.1.1``. HQ has
six DHCP clients (``.10``–``.15``) and Branch four (``.10``–``.13``).
``two_sites_overlap_untagged.pcap`` is the same without VLAN tags, so only the
DHCP servers' MACs, domains and lease times separate them. Upload either: the
Overview shows **2 networks share 192.168.1.0/24**, with ``.1`` and
``.10``–``.13`` on both.
