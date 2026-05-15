Cross-PCAP Comparison
=====================

The **Multi-Analysis** feature lets you load two or more PCAP files into a
single unified network topology diagram, so you can compare traffic patterns
across captures side by side.

Starting a Comparison
---------------------

1. From the **All Uploads** file list, check the checkboxes on two or more
   fully-processed PCAP files.
2. Click the **Multi-Analysis (N)** button that appears in the header.
3. A modal appears with two options:

   - **View Together** — navigates to ``/compare?files=id1,id2,…`` and
     renders the merged topology immediately. The original files are unchanged.
   - **Merge & Analyze** — permanently merges the selected PCAPs into a new
     single file (named automatically or as you specify), runs the full
     analysis pipeline on the merged file, and navigates to its analysis page.

The Comparison View
-------------------

The comparison view is a React Flow graph identical to the single-file
**Network Diagram**, with the following additions:

Source-aware rendering
~~~~~~~~~~~~~~~~~~~~~~

Each node and edge carries a ``sources`` list recording which uploaded files
contributed it:

- **Solid border / solid edge** — present in the primary (first selected) file.
- **Dashed border / dashed edge** — present only in a secondary file.
- **Thick edge (2.5 px)** — present in two or more files simultaneously.
- A ``bi-layers`` badge appears on nodes that exist in multiple captures.

File toggle pills
~~~~~~~~~~~~~~~~~

A row of color-coded pills (one per file, labelled by filename) appears above
the graph. Clicking a pill hides all nodes and edges that are exclusive to
that file, letting you isolate traffic from a single capture.

Filters and layout
~~~~~~~~~~~~~~~~~~

All filters available in the single-file Network Diagram (protocol, IP, port,
risk, device type, grouping, layout algorithm) work identically in the
comparison view. Filters apply to the merged dataset.

Node merging logic
~~~~~~~~~~~~~~~~~~

Nodes are matched across files by **IP address**. If the same IP appears in
two files with *different* MAC addresses (e.g. DHCP lease reuse), the backend
keeps them as separate nodes rather than incorrectly merging them.

Export
------

The **Export PDF** button in the comparison view captures the merged topology
and includes it in the PDF report alongside any other active analysis sections.

Permanent Merge
---------------

Choosing **Merge & Analyze** calls ``POST /api/files/merge``, which:

1. Downloads all selected PCAP files from MinIO.
2. Concatenates them with ``mergecap``.
3. Uploads the result as a new file and triggers the standard analysis
   pipeline (tshark parsing, nDPI, geolocation, file extraction).

The merged file appears as a regular entry in the file list and can be
analysed, compared, or deleted independently of the originals.
