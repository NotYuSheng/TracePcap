Network Map Layout
==================

The **network map** is a layout of the network graph that draws the capture the
way an analyst would by hand: devices grouped into nested boxes by where they
are, every level shown. It's the layout the Network Visualization page opens
in; the layout controls (bottom right) switch to circular or hierarchical and
back. The compare page and the monitor's snapshot dialog open in circular.

.. figure:: images/network-map-two-sites.png
   :alt: The network map of two_sites_one_range.pcap: Your networks holds two networks,
         hq.corp.example (VLAN 10) and branch.corp.example (VLAN 20), each with its 192.168.1.0/24
         subnet and device-family groups; Internet and Broadcast and multicast sit beside it.

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
    network** when the capture has no DHCP at all). A statically addressed
    host (a server, a printer) joins the network whose range holds its
    address, when exactly one network has that range.

    - **Subnet**: the /24 (IPv4) or /64 (IPv6).

      - **Device family**: the kind of device, by its classification:
        Servers (DNS, web, API and other servers together), Routers,
        Laptops and desktops, Phones and tablets, IoT devices, Layer-2
        devices, Virtual addresses, or Unclassified. Each device's own label
        still gives its exact type.

- **Internet**: public addresses, grouped by **domain** (``cdn.example.com``
  and ``www.example.com`` share ``example.com``). The domain comes from the
  host's name, else from the name clients looked its address up by in the
  capture's DNS traffic; with neither, **No hostname**.
- **Broadcast and multicast**: ``0.0.0.0``, ``255.255.255.255`` and multicast
  addresses.

Device labels are fitted to their cell, so neighbours never overlap: with the
whole map in view a device shows its first lines (name and address), cut to fit,
and zooming in shows the rest. Hover a device to read all of it.

Each network has its own colour. A router that serves several networks from one
MAC address shows once per network: each of its addresses goes in the network
whose range holds it. A box's name shows how many devices it holds;
when it's too small to read at the current zoom, it's left out until you zoom
in. Two networks that use the same range stay apart: a device on the second one
is placed by its device key, else by its MAC.

Trying It Out
-------------

``sample-files/small_office.pcap`` (made by ``gen_small_office.py``) fills every
level: three DHCP networks (staff, devices, guest), a statically addressed
server network, internet hosts named by DNS lookups, traffic between the
networks, and 26 minutes for the time axis to play (the cameras start at 5
minutes, a visitor's phone joins at 15).

.. figure:: images/network-map-small-office.png
   :alt: The network map of small_office.pcap: staff, devices and guest networks with their
         subnets and device-family groups, Other local addresses holding the servers, and the
         internet grouped into bbc.co.uk, example.co.uk, github.com, google.com, microsoft.com
         and office365.com.

   ``small_office.pcap``.

``sample-files/site_to_site_vpn.pcap`` (``gen_site_to_site_vpn.py``) is two
offices joined over the internet: each LAN sits behind a gateway that runs DHCP,
DNS and NAT, and the gateways run a WireGuard tunnel between their public
addresses. On the map the two offices are side by side under *Your networks*;
the gateways' public addresses sit together in the Internet box (named by
reverse DNS, so both fall under ``acme.example``), joined by the tunnel; long
edges run from Branch's PCs and till to the HQ file and ERP servers (the traffic
inside the tunnel, captured on each LAN); and each public address fans out to
the sites the offices browse. A gateway's inside and outside addresses are
separate devices on the map: nothing in the capture ties them together.

.. figure:: images/network-map-site-to-site.png
   :alt: The network map of site_to_site_vpn.pcap: hq.acme.example and branch.acme.example under
         Your networks, the two gateways' public addresses together under acme.example in the
         Internet box, and edges from the Branch devices to the HQ servers.

   ``site_to_site_vpn.pcap``.

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

Exporting to draw.io
--------------------

The **download** button in the graph card's header saves the network map as a
draw.io diagram (``<capture>-network-map.drawio``), to open in draw.io (desktop
or web) and finish by hand:

- every box is a draw.io container, nested as on the map, so moving a box
  carries everything in it;
- every device is one of draw.io's network shapes (server, router, laptop,
  phone, switch; a circle when the type is unknown), labelled with the same
  lines as on screen (see *Customize node labels*);
- every pair of devices that talked is joined by one line, in its protocol's
  colour.

The diagram opens laid out the way TracePcap drew it. It always uses the
network map's grouping, whichever layout is showing, and only the devices the
current filters leave on the graph.

Your Own Groups, Names and Notes
--------------------------------

**Groups** (in the graph card's header, with the network map showing) lists every
group of the map as a tree. There you can:

- **Add a group of your own**: give it a name (``Payments (PCI scope)``) and pick
  the group it goes **inside** (a network, a subnet, *Your networks*…: any box that
  holds groups rather than devices). It shows as a box saying *Drop devices here*;
  drag devices into it on the map.
- **Rename** any group: *staff.office.example (VLAN 10)* can read *Staff*. The list
  keeps the automatic name (*renamed from …*); clear the name to go back to it.
- **Add a note** to any group (owner, location, purpose). It shows under the
  group's name on the map, when zoomed in enough to read it.
- **Delete** a group of your own. Devices moved into it go back to their automatic
  groups.

Clicking a box's name on the map opens the list on that group. Names, notes and
your groups are saved with the capture like moves, are in the draw.io download,
and need the same **Edit network maps** permission; **Reset map** clears them too.

Moving Devices Between Groups
-----------------------------

The automatic grouping is a starting point. To put a device somewhere else (a
static server the map filed under *Other local addresses*, a phone you know
belongs with the tills), **drag it onto another box**: while you drag, the box
it would go into lights up; drop it there and it moves. Dropped anywhere else,
it goes back to its own box: a device always sits in a box.

- The move is **saved with the capture**, for everyone who opens it, and kept
  when filters, the time axis or packet replay change what's shown. A box a
  device was moved into says so (*2 moved here*).
- **Undo move** (in the graph card's header) takes back your last moves, one at
  a time. **Reset map** puts every moved device back in its automatic group,
  after asking.
- Moving needs the **Edit network maps** permission (analysts, by default);
  without it a dropped device goes back. Every change is in the audit log.
- If a move no longer fits (the device is filtered away, or re-analysis files
  it under a different group), it's skipped and the device shows in its
  automatic group.
- The draw.io download includes the moves.
