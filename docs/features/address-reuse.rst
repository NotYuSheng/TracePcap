Devices on an Address
=====================

An IP address can pass from one device to another during a capture. DHCP hands
a laptop's address to a phone once the laptop leaves, or a machine is replaced
mid-capture. TracePcap works out which devices held the address and when,
classifies each one from its own traffic, and draws each as its own node in the
network graph, so one device's traffic isn't blamed on another.

Where It Shows
--------------

Open a host's details (from the network graph, a conversation, or the monitor
views). Under its identity, **Devices on this address** lists each device in
time order:

- the time range it held the address;
- its MAC and, when DHCP gave one, its hostname;
- how many of the address's conversations started in that range;
- its own device type, confidence, vendor and TTL, for example
  ``Mobile · 67% · Samsung Electronics · TTL 64`` (see below);
- the evidence for the change, for example
  ``ARP: bb:bb:bb:00:00:01 last seen 10:59:58, then cc:cc:cc:00:00:02 from 11:00:02``.

An address held by one device says **One device for the whole capture**.

In the Network Graph
~~~~~~~~~~~~~~~~~~~~

An address more than one device held is drawn as **one node per device**,
labelled with the device's hostname (or ``10.0.0.50 · 2/2`` when it has none).
Each conversation goes to the device that held the address when the
conversation started, so the edges, traffic totals and alerts sit on the right
device. An address one device held throughout stays a single node.

Clicking a device's node opens its details, with **this node** marked in the
device list. The **Identity**, role and evidence shown are that device's.

How Changes Are Found
---------------------

An address is split **only when a different MAC takes it over**:

- **ARP:** a different hardware address claims the IP ("this address is mine").
- **DHCP:** the address is leased to, or requested by, a different client MAC.

Each MAC's claims have a first and last time. When one MAC's claims end before
the next one's begin, the next MAC starts a new device. When two MACs claim the
address **at the same time**, that's an address conflict, not reuse, and nothing
is split. The details say so.

Some things never split an address on their own:

- **A different TTL or hostname** with the same MAC. One machine rebooting into
  another operating system looks the same. These still show as the *Possibly
  more than one machine* warning, and are offered as suggestions when you split
  by hand.
- **Off-subnet addresses.** There's no ARP for them, and their frames carry the
  router's MAC.
- **Router failover addresses** (VRRP, HSRP, CARP), which are shared by design.

When an address is split, it shows its devices instead of the *Possibly more
than one machine* warning, because the differing TTLs and names belong to
different devices.

Each Device's Own Classification
--------------------------------

Each device is classified by the same classifier as any host, from only what
happened while it held the address:

- the address's conversations that started in its time range;
- its own MAC, so the vendor (Dell, Samsung…) is its own;
- the TTL the address sent with during its range, so a Windows laptop's 128
  isn't counted for the phone that came after it;
- its DHCP hostname, and Windows sign-ins first seen in its range;
- votes from detection rules that matched one of its conversations.

Service roles, such as a DNS server, are the address's, since the service logs
aren't split by time.

Splitting or merging by hand (below) classifies the new devices straight away.

Correcting It
-------------

The evidence can be wrong both ways, so you can correct it:

- **Split by time…** when you know it's two devices that the evidence didn't
  split: cloned VMs with one MAC, a re-imaged machine, an off-subnet address.
  Pick one of the suggested points (a MAC first claiming the address, a DHCP
  hostname appearing, a long silence) or enter a time, and give a reason. A
  split needs activity on both sides.
- **Not a different device?** on an automatic split merges it back, for example
  a phone rotating its private MAC address, or a replaced network card. Give a
  reason.

Each correction is shown with who made it and why, can be undone, and is
recorded in the audit log. Corrections are kept apart from the computed result,
so they survive the result being recomputed, and a
:doc:`re-analysis <reanalysis>` version starts with its original's corrections.

Who can make corrections is the **Split, merge or link devices** permission
on the Settings page's **Permissions** tab (default: analysts; see
:ref:`settings-permissions`).

Labels on One Device
--------------------

On an address more than one device held, the **Identity** panel, the role and
any evidence you add are about **one device**. The device list marks which one
(**this node** when opened from the graph, **showing** otherwise), and **Show
this device** switches to another. Opened from anywhere but the graph, the first
device is shown.

So a label you set ("Visitor phone, suspicious") stays on the phone and doesn't
spread to the laptop that held the address before it.

- **The first device keeps the address's own key.** A label you set before the
  address was split stays with whichever device held it first.
- **A split** keeps labels with the part that contains the device's start.
- **A merge** moves the later device's labels, role and evidence to the joined
  device. If the joined device already has its own label, the later device's is
  kept aside. **Undoing the merge** moves them back.
- **In the next monitor snapshot**, a device's label follows its **MAC**, since
  its address and times change. A label on an address one device held still
  carries by IP, as before.

Try It
------

A walkthrough with screenshots: :doc:`../demos/devices-on-a-dhcp-network`.

``sample-files/dhcp_address_reuse.pcap`` is an office Wi-Fi capture from 10:00
to 12:00: Alice's Dell laptop holds ``10.0.0.50`` until 10:59, and a visitor's
Samsung phone gets the same address at 11:00 and starts beaconing to a
suspicious domain at 11:32. Upload it and open the Network Graph: the address
is two nodes, ``LAPTOP-ALICE`` and ``Galaxy-S24``, and the beacon's edges are on
the phone. :doc:`../sample-files` has the generator script.

What This Doesn't Change Yet
----------------------------

- **Notes** are still per address (or per MAC, on a device's MAC).
- Story, reports, the network cluster view and the monitor views use the
  address's classification.
- Re-applying detection rules re-scores the address, not each device.
- The same device on different addresses, across captures, isn't recognised as
  one device yet (#918).
