nDPI Security Analysis
======================

When **nDPI Analysis** is enabled at upload time, each conversation is
inspected by **nDPI v5** (deep packet inspection library) in addition to
standard Wireshark/tshark parsing.

What nDPI Provides
------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Data point
     - Description
   * - Application name
     - Identified application (e.g. ``TLS``, ``HTTP``, ``DNS``, ``Telegram``,
       ``TOR``, ``Dropbox``, …) — over 300 protocol/app signatures.
   * - Category
     - Traffic category (e.g. ``Web``, ``VPN``, ``Social Network``,
       ``Malware``).
   * - Risk flags
     - Per-conversation risk alerts such as ``KNOWN_PROTOCOL_ON_NON_STD_PORT``,
       ``SELF_SIGNED_CERTIFICATE``, ``SUSPICIOUS_DGA_DOMAIN``,
       ``CLEAR_TEXT_CREDENTIALS``, and many others.
   * - JA3 fingerprint
     - Client TLS fingerprint (MD5 of TLS ClientHello parameters).
   * - JA3S fingerprint
     - Server TLS fingerprint (MD5 of TLS ServerHello parameters).
   * - SNI (Server Name Indication)
     - Hostname extracted from TLS ClientHello.
   * - TLS certificate metadata
     - Subject CN, issuer, validity dates, certificate version.

Viewing nDPI Results
--------------------

nDPI data surfaces across multiple views:

- **Overview tab** — summary counts of detected applications, categories,
  and risk alerts.
- **Conversations tab** — per-row columns for Application, Risk, JA3, JA3S,
  and SNI; filterable by any of these fields.
- **Node Detail Panel** — risk badges on individual host nodes in the network
  graph.

Risk Flags
----------

Risk flags are colored badges displayed alongside conversations:

- ``critical`` — red
- ``high`` — orange
- ``medium`` — amber / yellow
- ``low`` — purple

Custom signature rules (see :doc:`custom-signatures`) add additional badges
to these nDPI-native detections.

Enabling nDPI
-------------

nDPI analysis is opt-in per upload. Enable the **nDPI Analysis** toggle in the
upload dialog before submitting the file. It cannot be added after upload —
re-upload the file with the toggle enabled if needed.

.. note::

   nDPI analysis increases processing time proportionally to file size, but
   runs fully offline inside the backend container.
