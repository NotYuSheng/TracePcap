Devices That Move to Another Address
====================================

A device can change address during a capture: a laptop leaves and comes back on
a new DHCP lease, or a cable is moved to another port. By address alone that's
two unrelated hosts. TracePcap recognises it as **one device moving**.

How a Move Is Found
-------------------

From the same evidence as :doc:`address-reuse`, read the other way round: the
**same MAC** claiming one address (ARP) or leased it (DHCP), and later a
different one.

- Only a **hand-over** counts: the MAC's time on the first address ended before
  its time on the next began. A MAC on two addresses at once is multi-homed (a
  router, an alias address), not moving.
- A device can move **any number of times**, and come back: ``.50``, then
  ``.73``, then ``.88``, then ``.50`` again is three moves. ARP and DHCP keep
  one first-to-last span per address, so on their own a return looks like
  being on both at once; the MAC's conversations settle it, showing when each
  address was actually in use. Two addresses in use at the same moment (a
  continuous session on one while the other is used, or the two seen within
  seconds of each other, again and again) is multi-homed; so is flapping back
  and forth more than a few times per address.
- Only conversations on addresses ARP or DHCP already tie to the MAC count, so
  a router's MAC on routed traffic (it carries far-away addresses) is never
  the router moving. A sparse conversation (DHCP renewals or ARP on the same
  ports, minutes apart) doesn't count as continuous use, and a conversation's
  MAC is taken from its first packet only, since one keyed by addresses can
  carry on with the next device after an address changes hands.
- A router failover pair's shared MAC (VRRP, CARP, HSRP) is never a move.
- Each move records when the device left, when it arrived, its hostname on each
  address, and what showed the new one (a DHCP lease, or ARP).

Where It Shows
--------------

- **Network graph:** a dashed **same device** line joins the device's two nodes,
  labelled with when it moved, and with a rename when its DHCP hostname changed
  (``renamed LAPTOP-ALICE → ALICE-WS01``). A device that went back and forth
  between the same two nodes gets one line whose label lists every move.
- **Node details:** *This device moved to 10.0.0.73 at 11:05* on the old
  address's node, and *was on 10.0.0.50 before 11:05* on the new one.

It works with shared addresses: in ``sample-files/dhcp_address_reuse.pcap``
Alice's laptop leaves ``10.0.0.50``, which a phone then gets, and comes back on
``10.0.0.73``. The line joins the laptop's node on ``10.0.0.50``, not the
phone's. :doc:`../demos/devices-on-a-dhcp-network` shows it.

``sample-files/device_roaming.pcap`` (``gen_device_roaming.py``) has a laptop
that moves three times and comes back (``.50`` → ``.73`` → ``.88`` → ``.50``),
next to a file server on two addresses at once that is, rightly, not a move.

Each address is still its own host for classification, labels and the rest; the
link shows they're one device.
