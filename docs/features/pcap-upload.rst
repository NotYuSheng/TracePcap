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

A single upload opens its analysis as soon as it is uploaded. With several
files, a dialog shows each one's progress. After upload you see a progress view showing each analysis
stage (packet parsing, nDPI analysis, geolocation, file extraction, …) with
a percentage indicator. Analysis runs asynchronously — you can navigate away
and return later.

Managing Uploads
----------------

The main file list shows all uploaded PCAPs with their status, size, upload
date, and detected statistics. You can delete a file from this view, which
removes both the database metadata and the object from MinIO.

Monitor Network files are **hidden by default** in this list to reduce clutter
when many snapshots have been uploaded. Use the **Show Monitor files** toggle
(top-right of the file list) to include them.

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
