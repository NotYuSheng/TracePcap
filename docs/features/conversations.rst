Conversations
=============

The Conversations tab lists every network flow (conversation) extracted from
the PCAP file — one row per unique 5-tuple (src IP, dst IP, src port, dst port,
protocol).

Columns
-------

The column set is configurable via the **Column Picker** button. Default
columns include:

- Source IP / Destination IP
- Source Port / Destination Port
- Protocol
- Application (nDPI)
- Category (nDPI)
- Risk flags
- Country (src / dst)
- Device type (src / dst)
- Bytes transferred
- Packet count
- Start / end timestamp
- Custom signature matches

Filtering
---------

The filter bar supports simultaneous filtering on:

- IP address (src, dst, or either)
- Port (src, dst, or either)
- Protocol (TCP, UDP, ICMP, …)
- Application name (nDPI)
- Risk level
- Custom signature rule name
- Device type
- Country
- Payload pattern (substring search across reconstructed payloads)

Multiple filters combine with AND logic.

Sorting
-------

Click any column header to sort ascending; click again for descending.
Multi-column sorting is supported — hold **Shift** and click a second column.

Pagination
----------

Results are paginated. The page size is configurable from 10 to 100 rows.

Session Reconstruction
-----------------------

Click the **eye icon** on any row to open the session reconstruction viewer
for that conversation — see :doc:`session-reconstruction`.

Export Options
--------------

- **Per-conversation PCAP** — download a PCAP containing only the packets
  for a single conversation via the row action menu.
- **Bulk PCAP export** — select multiple rows (or all) and export them as
  a combined PCAP.
- **CSV export** — export the current filtered and sorted view to CSV.
