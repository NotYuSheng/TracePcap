Where the Traffic Goes
======================

Two cards on a capture's :doc:`analysis-overview` show who the capture's hosts
talk to, grouped by organisation or country: **Where the traffic goes** and
**Flows between organisations**. They replace the old Cluster tab, which grouped
hosts because the network diagram couldn't draw them all; the diagram now draws
every host (see :doc:`network-visualization`), so what remains is the summary by
group.

Where the Traffic Goes
----------------------

Each host is put in a group, shown as a tile as big as the traffic its hosts sent
and received. The 16 largest groups get a tile each; the rest share one *smaller
organisations* tile, so the long tail stays readable.

The switch above the tiles picks the grouping:

- **Organisation**: the network that owns the address, its ASN, from the GeoIP
  data (ipinfo.io when the internet is reachable, the bundled DB-IP database when
  not). An address in a range you labelled under **Network labels** (Settings ›
  Address defaults › Organisations, or a network's own Addresses) shows as that
  label first. Label your own public range, and it shows as yours, not as your
  ISP.
- **Country**: the address's country, from the same GeoIP data.
- **Map**: the countries on a world map, shaded by traffic. Click a country to
  see its cities.

Private addresses are **your networks** (purple); addresses with no organisation
or country in the GeoIP data are **unknown** (grey).

Click a tile, or focus it and press Enter, to open the group in a side drawer:

- its hosts, traffic, conversations and risks;
- its **hosts**, busiest first, each with its traffic and conversations. Click an
  address for its identity card. Past ten, a search box and **Show all** appear;
- the groups it **talks to**, by the traffic between them.

Flows Between Organisations
---------------------------

The largest flows between two organisations, as a flow diagram: senders on the
left, receivers on the right, each band as thick as the bytes between the two and
coloured by the protocol that carried most of it. Hover a band for its numbers.
**All flows** lists every pair with its traffic and conversation count.

Traffic between two hosts of the same organisation isn't a flow between two
organisations, so it isn't drawn here; it counts in that organisation's own
traffic in the drawer.

Old links to the Cluster tab (``/network-cluster`` and the older
``/network-intelligence``) open the Overview.
