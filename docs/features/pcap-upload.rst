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

The default maximum file size is **512 MB**, configurable via the
``MAX_UPLOAD_SIZE_BYTES`` environment variable (see
:doc:`../configuration/environment-variables`).

Upload Options
--------------

Both analysis stages run automatically on every upload by default:

- **Protocol & application classification** (nDPI) — application
  identification, risk detection, TLS metadata, JA3/JA3S fingerprints
  (see :doc:`ndpi-analysis`).
- **Embedded file extraction** — HTTP object and raw stream extraction from
  TCP/UDP payloads (see :doc:`file-extraction`).

If the deployment has ``VITE_ANALYSIS_OPTIONS=true`` set, an
**Analysis options** modal appears after file selection, allowing each
stage to be disabled individually for that upload (useful for reducing
processing time on large captures).

Duplicate Detection
-------------------

TracePcap computes a **SHA-256** hash of each uploaded file by streaming it
through a ``MessageDigest``. If a file with the same hash already exists in
the database, the upload is rejected and you are linked to the existing
analysis. This prevents redundant processing and storage.

Processing Progress
-------------------

After upload, you are redirected to a progress view showing each analysis
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
