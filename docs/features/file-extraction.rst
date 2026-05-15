File Extraction
===============

File Extraction recovers objects transmitted over the network — images,
documents, binaries, archives, and more — directly from PCAP payloads.

Enabling Extraction
-------------------

Enable the **File Extraction** toggle in the upload dialog before submitting
the PCAP file. Like nDPI analysis, it cannot be added retroactively.

Extraction Methods
------------------

TracePcap uses two complementary extraction techniques:

HTTP Object Extraction
~~~~~~~~~~~~~~~~~~~~~~

For HTTP/1.x conversations, the backend parses HTTP response headers and
extracts the response body as a file object. The original filename (from
``Content-Disposition``) and MIME type (from ``Content-Type``) are preserved
where available.

Stream Extraction (Aho-Corasick)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For non-HTTP traffic or when HTTP parsing fails, TracePcap scans raw TCP and
UDP stream payloads using an **Aho-Corasick** multi-pattern search to locate
known file magic bytes (e.g. ``%PDF-``, ``PK\x03\x04`` for ZIP, ``\xFF\xD8``
for JPEG, …). Matching byte sequences are carved out as candidate files.

MIME Detection
--------------

Every extracted file is passed through automatic MIME type detection based on
its content (magic bytes), independent of any filename extension or HTTP
header. This ensures correct identification even when headers are absent or
misleading.

Viewing Extracted Files
-----------------------

Go to the **Extracted Files** tab for a PCAP. Each file is listed with:

- Filename (original or auto-generated)
- MIME type
- Size
- Source conversation (src IP : src port → dst IP : dst port)
- Extraction method (HTTP / stream)

Bulk Download
-------------

Select multiple files and click **Download Selected** to receive them in a
ZIP archive. Individual files can be downloaded directly via the row action
button.
