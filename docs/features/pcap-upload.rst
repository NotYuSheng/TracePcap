PCAP Upload & Management
========================

TracePcap accepts PCAP, PCAPNG, and CAP files via a drag-and-drop interface.
Files are stored in MinIO object storage and analysed asynchronously.

Supported Formats
-----------------

- ``.pcap`` — libpcap format
- ``.pcapng`` — next-generation capture format
- ``.cap`` — Wireshark capture format

Upload Limit
------------

The default maximum file size is **512 MB**. It is derived from the
``APP_MEMORY_MB`` memory budget (max upload = 25% of it), not set directly —
see :doc:`../configuration/environment-variables`.

The Home Page
-------------

The home page has two columns:

- **Analyse a capture** on the left: the drop zone, the analysis stages
  ("Analyse with", below), and how long captures are kept.
- On the right, **Recent activity** with **All Uploads** under it, five captures to a page.

**Recent activity** shows the three latest events:

- captures analysed, still analysing or failed, each linking to its analysis;
- captures due for deletion within three hours, at the top;
- the latest change people made, taken from the audit log. A run of edits to
  one network map is one line, linking to that capture's map.

**All changes** opens the full audit log in Settings.

With no captures yet, the page is a first-run screen instead: what TracePcap
does, the same drop zone and stages, and the three steps.

Analyse With
------------

The stages to run are on the home page, under the drop zone. Set them before
you choose files; there is no popup afterwards.

- **Protocols and apps** (nDPI): application identification, risk detection,
  TLS metadata, and JA3/JA3S fingerprints (see :doc:`ndpi-analysis`). On by
  default.
- **Intrusion alerts** (Suricata): known attack signatures. **Off by
  default**, because it is the slowest stage.
- **Files in the traffic**: HTTP object and raw stream extraction from
  TCP/UDP payloads (see :doc:`file-extraction`). On by default.

Turning a stage off shortens analysis of a large capture.

Duplicate Detection
-------------------

TracePcap computes a **SHA-256** hash of each uploaded file by streaming it
through a ``MessageDigest``. If a file with the same hash already exists in
the database, the upload is rejected and you are linked to the existing
analysis. This prevents redundant processing and storage.

Processing Progress
-------------------

The whole **Analyse a capture** panel is the drop target. While you drag
files over it, it says how many captures will be analysed and with which
stages.

Each file then becomes a row in the panel, with no dialog, so the rest of the
page stays usable:

- **Uploading**: a bar and how much has been sent.
- **Analysing**: the current stage, e.g. "Stage 2 of 5: Detecting applications
  & threats".
- **Ready**: the packet count and an **Open** button.

Problems stay as rows with a plain reason:

- a file **already analysed** is not uploaded again, and the row links to its
  analysis;
- a file that is **too big** or **not a capture** says so, and what to do.

**Clear these** removes the finished rows. **Add more** picks more files while
others are still going.

A single file opens its analysis as soon as it is uploaded, on a progress view
that shows each stage. Analysis runs in the background, so you can leave and
come back.

Managing Uploads
----------------

**Your captures**, on the home page under Recent activity, lists each capture.
Each row has its name (a link to its analysis), its size, packet count and
upload time, its status, and a **⋯** menu with **Open**, **Re-analyse…** and
**Delete**. Deleting removes both the database metadata and the object from
MinIO.

Above the list:

- **Search** matches capture names.
- **Chips** narrow it to **Expiring soon**, **Kept with a network** or
  **Failed**, each with its count.
- **Show monitor uploads** adds captures uploaded straight into a monitored
  network. They are hidden by default.

Tick captures to select them, across pages if you like. A bar then appears at
the foot of the list:

- **Compare**: view two or more together (see :doc:`comparison`).
- **Merge into one**: combine them into a new capture and analyse it.
- **Delete N**: delete the selected captures.
- **Clear**: drop the selection.

Each capture has exactly one **status**, in its own column:

.. list-table::
   :header-rows: 1
   :widths: 20 50 30

   * - Status
     - Means
     - Button
   * - Queued
     - Uploaded, waiting for analysis to start.
     - Watch
   * - Analysing
     - Being analysed.
     - Watch
   * - Ready
     - Analysed and kept.
     - Open
   * - Expiring soon
     - Ready, but deleted within two hours by file retention. The row says
       how long is left.
     - Open, Keep it
   * - Failed
     - Analysis stopped. Open it to see why.
     - See why

Anything else is a grey **note** under the name, only when it applies:

- **Kept with <network>**: the capture is a snapshot of that monitored network,
  so file retention never deletes it. The note links to the network.
- **Without Suricata** (or nDPI, or file extraction): that tool was switched
  off at upload. This is a choice, not a fault.
- **Rules changed since**: detection rules changed after the capture was
  analysed. The note links to the rules in Settings, where you can re-apply
  them.
- **Packets removed**: packet retention deleted the raw packets. The
  conversations and results remain.

File Retention
~~~~~~~~~~~~~~

By default, uploaded files are automatically deleted **12 hours** after upload.
This window is configurable via the ``FILE_RETENTION_HOURS`` environment
variable. Set ``FILE_RETENTION_ENABLED=false`` to disable automatic deletion
entirely (see :doc:`../configuration/environment-variables`).

.. note::

   Monitor Network files are **exempt by default** from automatic deletion.
   They persist until you manually delete the network or the individual
   snapshot, unless a custom monitor retention period is explicitly configured.
   This includes a capture uploaded for analysis and later added to a network:
   from then on it follows the monitor retention, not ``FILE_RETENTION_HOURS``.
