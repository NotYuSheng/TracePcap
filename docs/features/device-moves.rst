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
- A router failover pair's shared MAC (VRRP, CARP, HSRP) is never a move.
- Each move records when the device left, when it arrived, its hostname on each
  address, and what showed the new one (a DHCP lease, or ARP).

Where It Shows
--------------

- **Network graph:** a dashed **same device** line joins the device's two nodes,
  labelled with when it moved, and with a rename when its DHCP hostname changed
  (``renamed LAPTOP-ALICE → ALICE-WS01``).
- **Node details:** *This device moved to 10.0.0.73 at 11:05* on the old
  address's node, and *was on 10.0.0.50 before 11:05* on the new one.

It works with shared addresses: in ``sample-files/dhcp_address_reuse.pcap``
Alice's laptop leaves ``10.0.0.50``, which a phone then gets, and comes back on
``10.0.0.73``. The line joins the laptop's node on ``10.0.0.50``, not the
phone's. :doc:`../demos/devices-on-a-dhcp-network` shows it.

Each address is still its own host for classification, labels and the rest; the
link shows they're one device.
