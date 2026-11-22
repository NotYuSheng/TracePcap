File Extraction
===============

File Extraction recovers objects transmitted over the network — images,
documents, binaries, archives, and more — directly from PCAP payloads.

Enabling Extraction
-------------------

File extraction is enabled by default. To skip it for an upload, untick
**Files in the traffic** under **Analyse with** on the home page before
choosing the file.

Either way, extraction cannot be added retroactively — re-upload the file
if you need extracted files for a capture processed without it.

Extraction Methods
------------------

TracePcap uses two complementary extraction techniques:

HTTP Object Extraction
~~~~~~~~~~~~~~~~~~~~~~

The backend runs ``tshark --export-objects http,<tmpdir>`` to extract HTTP
response bodies as files. A second tshark pass correlates each exported file
back to its source conversation by the name tshark gives it: the last part of
the request URI, query string included, with ``?`` and other characters a
file name can't hold percent-encoded (``/managements?id=1`` becomes
``managements%3fid=1``). Each file also records its **source URL**
(``http://host/path?query``), shown under its name and searchable.

A file is named what the server called it when it said so (the
``Content-Disposition`` header: ``Invoice 876597035_003.zip``, not
``managements%3f16553a…``); otherwise it keeps tshark's name.

Stream Extraction (Aho-Corasick + Apache Tika)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For non-HTTP traffic, TracePcap reconstructs raw TCP/UDP stream payloads for
candidate conversations (up to 50 streams per PCAP) and scans them using an
**Aho-Corasick** multi-pattern search for known file magic byte sequences
(e.g. ``%PDF-``, ``PK\x03\x04`` for ZIP, ``\xFF\xD8`` for JPEG). Each
candidate match position is then confirmed by **Apache Tika**, which performs
a definitive magic-byte check. This O(n) approach replaces a sliding-window
scan and keeps Tika calls proportional to actual matches rather than stream
length.

A maximum of 5 files per stream are extracted to prevent runaway extraction
on synthetic or binary-heavy payloads.

Two kinds of stream are never carved, because any "file" found in them is a
coincidence of bytes:

- **Encrypted streams** (TLS, QUIC, SSH and VPN protocols, or any stream with a
  TLS handshake): the payload is ciphertext.
- **Streams already exported as HTTP objects**: carving only finds fragments of
  the same files again.

Carved files are guesses either way. The **Downloaded file** answer in the
Investigation panel only ever lists files from a real HTTP transfer.

MIME Detection
--------------

Every extracted file — from either method — is passed through **Apache Tika**
for content-based MIME type detection. This is independent of any filename
extension or HTTP header, ensuring correct identification even when headers
are absent or misleading. Tika also resolves the appropriate file extension
from the detected MIME type.

Size Limit
----------

Individual extracted files larger than **50 MB** are discarded to avoid
excessive MinIO storage consumption.

Viewing Extracted Files
-----------------------

Go to the **Extracted Files** tab for a PCAP. Each file is listed with:

- Filename (original or auto-generated)
- MIME type (Tika-detected)
- Size
- Source conversation (src IP : src port → dst IP : dst port)
- Extraction method (``tshark_http`` / stream)

MIME Type Filter
~~~~~~~~~~~~~~~~

A collapsible **Filters** panel above the file list shows pill buttons for
every MIME type present in the loaded files. Select one or more to narrow the
list. The file count badge updates to ``X / Y files`` while a filter is
active. **Select All** and **Clear** shortcuts appear in the pill header.

Media Preview
~~~~~~~~~~~~~

Files with a browser-natively playable MIME type (images, audio, video) show
a **Preview** button. Clicking it opens an inline modal with the file rendered
directly in the browser — no download required. The preview endpoint returns
``Content-Disposition: inline`` so the browser handles rendering.

Download Safety Disclaimer
~~~~~~~~~~~~~~~~~~~~~~~~~~

Clicking **Download** on any extracted file shows a safety disclaimer modal
before the download begins, reminding you that extracted files may be
malicious.

Bulk Download
-------------

Select multiple files and click **Download Selected** to receive them in a
ZIP archive. Individual files can be downloaded directly via the row action
button.
