Getting Around a Capture
========================

A capture's analysis has eight sections. They're on a **rail down the left edge**
of the window, each an icon over a short name. The rail stays in place under the
header as you scroll:

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - On the rail
     - Section
   * - Overview
     - The summary: what's in the capture, findings, risks.
   * - Conversations
     - Every conversation, with filters (see :doc:`conversations`).
   * - Story
     - A written account of the capture (see :doc:`story-mode`).
   * - Network
     - The network graph: map, circular or hierarchical (see :doc:`network-visualization`).
   * - Cluster
     - Hosts grouped by country, organisation and more (see :doc:`network-cluster`).
   * - Files
     - Files carried in the traffic.
   * - Filters
     - Wireshark display filters from plain English.
   * - Capture
     - The capture file itself: details, re-analysis, versions.

The **»** button at the bottom widens the rail to show the sections' full names
(*Network Visualization*, *Extracted Files*…); **«** narrows it again. The choice
is remembered in this browser. On a phone the rail is a row across the top that
scrolls sideways.

Above every section, the **capture bar** says which capture you're in (its name,
packets and length, with a link back to all captures) and holds what applies to
the whole capture: **Custom detection rules** (which network's rules to include,
see :doc:`custom-signatures`) and **Download report**.
