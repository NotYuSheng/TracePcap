Network Cluster
===============

The **Network Cluster** tab presents a high-level cluster graph that
groups all IP addresses in a capture into named clusters, making it easier to
understand traffic between organisations, countries, subnets, or device
classes at a glance.

Cluster Graph
-------------

Each cluster node represents a group of IPs. Edges between clusters represent
observed conversations between IPs in those groups. Clicking a cluster opens
a side panel listing the individual IPs it contains, with per-IP metrics and
a conversation list.

Grouping Strategies
-------------------

Select a strategy from the **Group by** dropdown:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Strategy
     - How IPs are grouped
   * - **ASN / Organization**
     - Autonomous System Number from ipinfo.io geo enrichment. Only available
       for IPs enriched online; offline DB-IP fallback does not provide ASN.
   * - **Country**
     - Country code from ipinfo.io (online) or DB-IP Lite (offline). Switches
       the canvas to the SVG world map view (see `Country Map View`_ below).
   * - **City**
     - ``<CountryCode>:<CityName>`` from the DB-IP Lite City MMDB. Falls back
       to ``unknown`` for unresolvable IPs.
   * - **Subnet /24**
     - First three octets of the IP (e.g. ``10.0.1.0/24``).
   * - **Subnet /16**
     - First two octets of the IP (e.g. ``10.0.0.0/16``).
   * - **Device Type**
     - Predicted device class from the multi-signal classifier (Router, Mobile,
       Server, etc.) — see :doc:`geolocation` for the scoring algorithm.
   * - **Network Labels**
     - Custom CIDR-to-label mappings defined in the **Network Labels** tab of
       the Custom Detection Rules modal — see :doc:`custom-signatures`. Only
       conversations where at least one endpoint is a labelled IP are shown;
       unlabelled-only traffic is suppressed.

Color Modes
-----------

Two color modes are available via the **Color by** toggle:

- **Traffic** — cluster nodes are shaded by ``totalBytes`` relative to the
  busiest cluster, using the shared volume color scale (see below).
- **Risk** — clusters with at least one nDPI risk flag show a red warning
  badge. Nodes without risk flags are neutral grey.

.. _shared-volume-scale:

The Shared Volume Color Scale
-----------------------------

Everywhere traffic volume is encoded as color — cluster nodes, the country map,
the node-to-node heatmap and volume-colored diagram edges (see
:doc:`network-visualization`) — the same scale is used, so a given shade always
means the same thing. It lives in ``frontend/src/utils/volumeColor.ts``.

Two properties are worth knowing when reading any of these views:

- **The scale is logarithmic.** Traffic volume is heavily skewed: a handful of
  pairs typically carry most of the bytes. On a linear ramp that yields one dark
  mark and a wash of pale ones. Note this means the midpoint of the legend is
  *not* half the maximum.
- **The scale is relative to what is on screen.** It normalizes against the
  busiest item in the current, filtered view — so changing filters re-fits the
  ramp, and shades are comparable within a view rather than across captures.

In dark mode the anchors flip: magnitude reads as distance from the surface, so
on a light background "loud" is dark blue, and on a dark background it is bright
blue. Marks that are stroked rather than filled (diagram edges) use a floored
variant of the ramp, so even the quietest edge stays visible instead of fading
into the canvas.

Cluster Side Panel
------------------

Clicking a cluster opens a panel on the right showing:

- The cluster label and IP count.
- A per-IP breakdown sortable by **Traffic** (bytes), **Conversations**,
  **Risk flags**, or **Unique peers**.
- A conversation list for the selected cluster, filtered by the active
  Network Cluster filters (same filter set as the Conversations tab).

Filters
-------

The Network Cluster tab exposes the full conversation filter panel
(IP, port, protocol, application, country, device type, risk, custom
signatures, etc.), identical to the Conversations tab. Filters apply to
both the cluster graph and the side-panel conversation list.

Country Map View
----------------

When **Group by = Country** is selected, the React Flow canvas is replaced
with a static SVG world map rendered from a bundled Natural Earth 110m
TopoJSON file (no tile server or internet connection required).

- Each country with observed traffic displays a **cluster marker** positioned
  at the country's geographic centroid.
- Marker size and shade reflect traffic volume (heatmap) or risk presence,
  consistent with the cluster graph color mode.
- **Click a country marker** to drill down: the map fetches city-level
  clusters for that country and displays them as smaller markers at their
  city coordinates.
- **Click a city marker** to open the cluster side panel for that city.
- The **Internal Network** cluster (RFC-1918 addresses) floats as a fixed
  card outside the map since it has no geographic position.
- A back button exits the drilled-down city view and returns to the country
  level.
