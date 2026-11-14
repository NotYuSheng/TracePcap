Network Map Layout
==================

The **network map** is a layout of the network graph that draws the capture the
way an analyst would by hand: devices grouped into nested boxes by where they
are, every level shown. Pick it with the **Network map** button among the
graph's layout controls (bottom right), next to circular and hierarchical.

.. figure:: images/network-map-two-sites.png
   :alt: The network map of two_sites_one_range.pcap: Your networks holds two networks,
         hq.corp.example (VLAN 10) and branch.corp.example (VLAN 20), each with its 192.168.1.0/24
         subnet and device-type groups; Internet and Broadcast and multicast sit beside it.

   ``two_sites_one_range.pcap``: two sites on the same range, each in its own box.

The Levels
----------

Each box sits inside the one above it:

- **Your networks**: local addresses (private ranges, plus your
  :doc:`custom private ranges <network-address-config>`).

  - **Network**: a network TracePcap found from DHCP and VLANs (see
    :doc:`overlapping-networks`), named by its DHCP domain and VLAN, with its
    range, gateway and DHCP server under the name. Local devices that no
    found network accounts for are in **Other local addresses** (or **Local
    network** when the capture has no DHCP at all).

    - **Subnet**: the /24 (IPv4) or /64 (IPv6).

      - **Device type**: the device's classification (Laptop / Desktop,
        Mobile, Server…), or **Unclassified**.

- **Internet**: public addresses, grouped by **domain** from their hostname
  (``cdn.example.com`` and ``www.example.com`` share ``example.com``), or **No
  hostname**.
- **Broadcast and multicast**: ``0.0.0.0``, ``255.255.255.255`` and multicast
  addresses.

Each network has its own colour. A box's name shows how many devices it holds;
when it's too small to read at the current zoom, it's left out until you zoom
in. Two networks that use the same range stay apart: a device on the second one
is placed by its device key, else by its MAC.

With the Time Axis
------------------

The layout works with :doc:`network-time-axis`. With a window set, devices
outside it go grey in place and each box counts what's active, such as *2 of 4
active*.

.. figure:: images/network-map-time-window.png
   :alt: The network map of dhcp_address_reuse.pcap with an early time window: box names read
         4 of 6 active, 1 of 3 active and so on, and quiet devices are greyed out.

   Early in ``dhcp_address_reuse.pcap``: the phone hasn't been active yet.

Edges, the traffic animation and the same-device links of :doc:`device-moves`
draw as in the other layouts.
