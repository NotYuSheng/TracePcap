PDF Report Export
=================

TracePcap writes a PDF report for any analysed capture. It is meant for someone who will never
open TracePcap: the first page says what needs a look, in sentences that name the devices, and
the evidence comes after.

Downloading a Report
--------------------

On the capture's **Capture** tab (*Capture, rules and report*), click **Download report**. A
drawer opens on the right:

**How much**
   - **Briefing**: what needs a look, the hosts by network, and the network map. Usually three
     pages.
   - **Full**: the briefing, then traffic, conversations, extracted files and an appendix of every
     flagged conversation.

**Include**
   Each part can be ticked on or off after picking one of the two. A part this capture can't have
   is greyed out with the reason, e.g. *Story: not written yet* or *Extracted files: extraction
   was off*, so the PDF never carries an empty section.

**Network map**
   - **As you left it**: the Network tab's map with its filters, which the PDF states under the
     map. Available once the Network tab has been opened.
   - **The whole capture**: every host, ignoring the Network tab's filters.

**Download PDF** draws the map, then builds the PDF. Progress shows in the drawer's footer.

What the Report Holds
---------------------

Every page has a running header and "n of N" in its footer, with the capture's name and the start
and end of its SHA-256.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Part
     - Contents
   * - **Summary** *(always)*
     - The capture's name, when it ran, its packets and size, and which detection rules it was
       read with. The figures: devices on your networks, networks, conversations, internet hosts.
       **Where the traffic goes**: the busiest organisations.
   * - **Needs a look**
     - What was flagged, most serious first. A flag on a few conversations is told one
       conversation at a time ("Telnet to CAM-ENTRANCE from Visitors-iPhone … at 17:25:00"),
       naming the device that held the address *at that moment*. A flag on a large share of the
       capture is one line, since that is more often a trait of the capture's devices than an
       attack. Also: an address that two devices held in turn, and devices that asked for an
       address and got no answer. Sources: nDPI risks, Suricata alerts and your detection rules.
   * - **Hosts, by network**
     - Hosts grouped by the network they're on (from DHCP: its domain or VLAN and range), then
       other local addresses, then the internet by organisation. Name, address, MAC, device type
       and vendor. A device that moved shows both addresses; an address two devices held shows
       both, with when; the gateway of each network reads as *Gateway*.
   * - **Network map**
     - The grouped map from the Network tab, fitted to the page, with what it shows under it.
       Then a list of the rest of the report, and what isn't in it and why.
   * - **Story**
     - The Story tab's narrative and findings, when written.
   * - **Traffic**
     - Every organisation, flows between them, protocols, applications and categories.
   * - **Conversations**
     - The 25 busiest conversations, by name, and every internet host with its organisation.
   * - **Extracted files**
     - Files carved from the capture, with type, size and SHA-256.
   * - **Appendix**
     - Every flagged conversation, grouped by flag (up to 300 per flag), and how each device was
       classified: its MAC vendor and TTL evidence and the confidence.

The map is a JPEG drawn at twice its printed size, so a report is usually around 1 MB.

Compare View Report
-------------------

The cross-capture comparison view (``/compare``) has its own **Export PDF** button that captures
the merged topology diagram and includes it in a comparison report.
