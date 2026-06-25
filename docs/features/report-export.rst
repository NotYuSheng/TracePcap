PDF Report Export
=================

TracePcap can generate a self-contained PDF report for any analysed PCAP.
The report is produced server-side and includes data from all analysis
stages completed for that file.

Generating a Report
-------------------

Click the **Export PDF** button in the top navigation bar of any analysis
page. A progress modal tracks the steps:

1. **Rendering network diagrams** — the frontend captures screenshots of
   the network topology in both Force-directed and Hierarchical layouts,
   using the currently active filters.
2. **Building PDF** — the backend assembles the report from stored analysis
   data and the captured diagram images.

The PDF downloads automatically when complete.

Report Sections
---------------

Sections are numbered consecutively. Optional sections are skipped (and
renumbered) when no data is available.

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Section
     - Contents
   * - **File Information**
     - Filename, SHA-256 hash, capture start/end times, duration, file size.
   * - **Executive Summary**
     - High-level counts: total conversations, unique hosts, risk alerts,
       protocols, applications, detected file types.
   * - **Protocol Distribution**
     - Bar chart and table of ``_ws.col.Protocol`` values by conversation
       count and byte volume.
   * - **Traffic Category Distribution**
     - nDPI traffic categories (Web, VPN, Media, etc.) by conversation count.
       Omitted if nDPI was not enabled.
   * - **Applications Detected**
     - nDPI application names ranked by conversation count. Omitted if nDPI
       was not enabled.
   * - **Detected L7 Protocols**
     - ``tsharkProtocol`` (deepest Wireshark dissector label) ranked by
       conversation count.
   * - **Host Inventory**
     - Table of all unique IPs with MAC address, vendor, device type,
       country, ASN, and risk alert count.
   * - **Risk & Signature Summary**
     - Counts of nDPI risk flags and custom signature matches.
   * - **Security Findings**
     - Up to the top 20 conversations with nDPI risk flags, showing src/dst,
       protocol, application, and risk names.
   * - **TLS / HTTPS Analysis**
     - Encrypted conversations with JA3/JA3S fingerprints, SNI, and
       certificate subject/issuer/expiry.
   * - **HTTP User Agents**
     - Distinct ``User-Agent`` strings observed across all HTTP conversations.
   * - **Top Conversations by Traffic**
     - Top conversations ranked by ``totalBytes``, with protocol, application,
       packet count, and byte volume.
   * - **Extracted Files**
     - List of files recovered by the extraction pipeline (filename, MIME
       type, size, source conversation). Omitted if extraction was not enabled.
   * - **Network Diagram — Active Filters**
     - Note of any active filters applied to the topology diagrams below.
   * - **Network Topology (Force-directed)**
     - Screenshot of the Sigma.js topology graph in force-directed layout.
   * - **Network Topology (Hierarchical)**
     - Screenshot of the Sigma.js topology graph in ELK hierarchical layout.
   * - **AI Narrative** *(if Story generated)*
     - The LLM-written narrative from Story Mode.
   * - **Deterministic Findings** *(if Story generated)*
     - Typed findings from the 8 detector algorithms (Beacon, TLS Anomaly,
       Volume, FanOut, etc.) with severity, affected IPs, and metrics.
   * - **LLM Investigation** *(if Story generated)*
     - Hypotheses, structured DB queries, and conversation evidence tables
       from the LLM investigation phase.

If Story Mode has not been run, a notice replaces the three story sections.

Network Diagrams in the Report
-------------------------------

The diagrams embedded in the PDF reflect **exactly what you see on the
Network Diagram tab** at the time you click Export PDF — including any active
protocol, IP, port, device type, or risk filters. Active filters are listed
in the preceding section so the report is self-documenting.

If the Network Diagram tab has not been visited in the current session, the
report fetches the raw graph and applies whatever filters are currently
configured in the diagram tab's filter panel.

The frontend temporarily switches to light mode before capturing screenshots,
so diagrams always render on a white background regardless of the user's
theme preference.

Compare View Report
-------------------

The cross-PCAP comparison view (``/compare``) has its own **Export PDF**
button that captures the merged topology diagram and includes it in a
dedicated comparison report.
