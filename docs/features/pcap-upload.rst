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

Before clicking **Upload** you can enable optional analysis modules:

- **nDPI Analysis** — deep packet inspection for application identification,
  risk detection, TLS metadata, and JA3/JA3S fingerprints
  (see :doc:`ndpi-analysis`).
- **File Extraction** — HTTP object extraction and raw stream extraction from
  TCP/UDP payloads (see :doc:`file-extraction`).

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
