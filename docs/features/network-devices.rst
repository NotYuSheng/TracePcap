Devices Across Snapshots
========================

A monitored network's **Devices** list shows each device once, wherever it was
on the network across the network's snapshots: a laptop that moved from one
address to another is one row, and two devices that shared an address (see
:doc:`address-reuse`) are two.

Open it from a monitored network's page with **Devices**.

What Each Row Shows
-------------------

- **Device:** its hostname in the latest snapshot it was seen in (or its
  address), and its device type.
- **MAC:** the address it's recognised by, its vendor, and a badge when the MAC
  is a virtual machine's, a container's, or private (below).
- **Addresses it used:** each address with the snapshots it used it in, for
  example ``10.0.0.50 snapshots 1–3`` then ``10.0.0.73 snapshot 4``.
- **Seen in:** one square per snapshot, filled where the device was seen.
- **Label:** your confirmed role label on it, from the latest snapshot that has
  one. Labels follow a device's MAC into later snapshots
  (:doc:`address-reuse`).
- **Irregularities:** anything that means the MAC may not stand for one machine.

Search matches name, MAC, address, vendor and label. **Irregular** and
**Private MAC** narrow the list. Click a device to see its address in each
snapshot, and open the latest snapshot it was seen in.

Only devices with a MAC of their own are listed. A host outside the local
network has none (its frames carry the router's MAC), and a router failover
pair's shared address isn't a device.

Irregularities
--------------

**Duplicate MAC?** (high)
   One MAC answering as two machines at once: TTLs from two operating-system
   families, or two DHCP hostnames, in the same snapshot. Cloned virtual
   machines and duplicated MACs do this.

**Virtual machine MAC** (medium)
   A hypervisor's prefix: VMware, VirtualBox, Hyper-V, QEMU/KVM, Xen or
   Parallels. Virtual machines cloned from one image often keep the same MAC,
   so it identifies a machine less reliably.

**Container MAC** (medium)
   Docker's ``02:42:…`` prefix: a container, not a physical device.

**Private MAC** (information)
   The MAC's locally-administered bit is set, so the device made it up rather
   than using its manufacturer's. Phones do this by default (iOS 14 and later,
   Android 10 and later), usually one per network, and newer versions can
   change it periodically. A private MAC names no vendor, and the same phone
   can appear under more than one.

Linking two private MACs that belong to one phone is planned (#918).
