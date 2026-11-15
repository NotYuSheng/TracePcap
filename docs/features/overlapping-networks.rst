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

One Device per Network
----------------------

An address used on two networks is **one device per network**, the same way an
address that changed hands is one device per holder (:doc:`address-reuse`):

- **Network graph:** one node per network, labelled with the machine's hostname
  there (for example ``HQ-LAPTOP-01`` and ``BR-TILL-01`` for ``192.168.1.10``).
- **Which conversation is whose** is told by **MAC**: each conversation records
  the MAC on each side. That's the machine itself, or for traffic from outside,
  the site's router. Both are known per network from the DHCP leases.
- **Classification:** each machine is classified from its own network's
  conversations, MAC and TTLs.
- **Host details:** **Devices on this address** lists the machine on each
  network. The **Identity**, label, role and evidence are for the one you pick,
  under its own key (the first network's machine keeps the address,
  ``192.168.1.10``; the other is ``192.168.1.10~<network>``).
- The host warns **Used on 2 networks that share this range (…): a different
  machine on each, shown as one device per network.**
- They aren't split or merged by time: two machines at once aren't one device
  handing an address over.

Networks are ordered by when they first leased an address, so which machine
keeps the bare address doesn't change between runs.

Subnets in Monitor
------------------

In a monitored network, subnet detection (**Subnet Definitions** → detect)
offers a range used by two networks **once per network**, each counting only that
network's addresses, for example ``192.168.1.8/29 on hq.corp.example`` (6 hosts)
and ``192.168.1.8/29 on branch.corp.example`` (4 hosts). Saved, each is its own
subnet with its own label, and its own staleness: its composition (members,
device types, protocols) counts only that network's machines and conversations.
A label for the range as a whole can sit beside them.

A network is recognised across snapshots by the same key (its VLAN, or its DHCP
server's MAC), so a per-network label carries on while that site's router stays
the same.

Limits
------

- Only addresses that got a DHCP lease, and the routers, can be placed on a
  network. A static address with no lease isn't assigned to either.
- Two conversations with the same addresses, ports and protocol on both networks
  are one conversation to TracePcap, recorded under the MAC seen first. Real
  machines pick their own ephemeral ports, so this is rare except for fixed-port
  traffic such as DHCP.
- A Windows sign-in records no MAC, so on a shared address it isn't placed on
  either network's machine.
- Elsewhere (Story, reports, the network cluster view, the monitor views) the
  address is still one host, as for addresses that changed hands.
- Only a monitored network's own subnet entries can be per network; the shared
  default (System → address defaults) is per CIDR.

Try It
------

A walkthrough with screenshots: :doc:`../demos/two-sites-one-range`.

``sample-files/two_sites_overlap.pcap`` has two sites, HQ (VLAN 10) and Branch
(VLAN 20), both on ``192.168.1.0/24`` with a router at ``192.168.1.1``. HQ has
six DHCP clients (``.10``–``.15``) and Branch four (``.10``–``.13``).
``two_sites_overlap_untagged.pcap`` is the same without VLAN tags, so only the
DHCP servers' MACs, domains and lease times separate them. Upload either: the
Overview shows **2 networks share 192.168.1.0/24**, with ``.1`` and
``.10``–``.13`` on both.
