Devices on an Address
=====================

An IP address can pass from one device to another during a capture. DHCP hands
a laptop's address to a phone once the laptop leaves, or a machine is replaced
mid-capture. TracePcap still treats an address as one host, but it shows which
devices held the address and when, so their traffic isn't mistaken for one
machine's.

Where It Shows
--------------

Open a host's details (from the network graph, a conversation, or the monitor
views). Under its identity, **Devices on this address** lists each device in
time order:

- the time range it held the address;
- its MAC and, when DHCP gave one, its hostname;
- how many of the address's conversations started in that range;
- the evidence for the change, for example
  ``ARP: bb:bb:bb:00:00:01 last seen 10:59:58, then cc:cc:cc:00:00:02 from 11:00:02``.

An address held by one device says **One device for the whole capture**.

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

Who can make corrections is the **Split or merge a host's devices** permission
on the System page's **Permissions** tab (default: analysts; see
:ref:`settings-permissions`).

What This Doesn't Change Yet
----------------------------

The address is still one host everywhere else: one classification, one node in
the graph, and labels and notes attach to the address. Classifying each device
separately, and showing one graph node per device, are planned (#918).
