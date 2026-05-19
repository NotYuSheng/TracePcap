Streaming / Automated PCAP Upload
==================================

TracePcap does not include a built-in folder watcher, but its REST API
makes it straightforward to automate uploads from any script or tool running
on any machine that can reach the TracePcap instance.

A ready-to-use script is provided at ``scripts/watch_and_upload.sh`` (Bash,
Linux / macOS). It uses ``inotifywait`` for event-driven watching with a
polling fallback if ``inotify-tools`` is not installed.

The typical flow is:

1. Upload the PCAP file → get back a ``fileId``.
2. Poll until analysis completes (``status == "COMPLETED"``).
3. Add the file as a snapshot to a Monitor network → change detection runs automatically.

API Endpoints Used
------------------

**Upload a PCAP file**

.. code-block:: http

   POST /api/files
   Content-Type: multipart/form-data

   file=<binary>                        (required)
   enableNdpi=true                      (optional, default true)
   enableFileExtraction=true            (optional, default true)

Returns JSON with ``id`` (the ``fileId``) and ``status``.

**Poll for analysis completion**

.. code-block:: http

   GET /api/files/{fileId}

Poll until ``status`` is ``COMPLETED`` before adding to a network snapshot.

**Add file to a Monitor network snapshot**

.. code-block:: http

   POST /api/monitor/networks/{networkId}/snapshots
   Content-Type: application/json

   {"fileId": "<fileId>"}

The snapshot is ordered automatically by the file's capture start time.
Change detection against the previous snapshot runs immediately.

Finding Your Network ID
------------------------

1. Open TracePcap and go to the **Monitor** tab.
2. Click on the network you want to stream into.
3. Copy the UUID from the browser URL bar:
   ``http://localhost:8888/monitor/<networkId>``

Usage
-----

**Bash**

.. code-block:: bash

   chmod +x scripts/watch_and_upload.sh
   ./scripts/watch_and_upload.sh /path/to/pcaps <networkId> http://localhost:8888

Requires ``curl`` and ``jq``.  Install ``inotify-tools`` for event-driven
watching (``apt install inotify-tools``); falls back to polling every 30
seconds otherwise.


Tips
----

- **Remote machine**: point the base URL at the TracePcap host,
  e.g. ``http://192.168.1.10:8888``.
- **File completion**: the Bash script uses ``close_write`` via
  ``inotifywait`` so it only triggers once the file is fully written.
  For the Python script, write files atomically (e.g. write to a ``.tmp``
  file then rename to ``.pcap``) to avoid uploading partial captures.
- **Running as a service**: wrap the script in a ``systemd`` unit or a
  Docker container for persistent background operation.
- **Duplicate detection**: TracePcap computes a SHA-256 hash of each
  upload and rejects duplicates automatically, so re-running the script
  over a directory that was already processed is safe.
- **First run**: both scripts skip files already present in the directory
  on startup and only upload files that appear after the script starts.
