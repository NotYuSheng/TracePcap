nDPI Security Analysis
======================

When **nDPI Analysis** is enabled at upload time, each conversation is
inspected by **nDPI v5** via the ``ndpiReader`` command-line tool
(``ndpiReader -i <file> -v 2``). The backend parses its per-flow output lines
in a single streaming pass and enriches each conversation record.

What nDPI Provides
------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Data point
     - Description
   * - Application name
     - Identified application (e.g. ``TLS``, ``HTTP``, ``DNS``, ``Telegram``,
       ``TOR``, ``Dropbox``, …) — over 300 protocol/app signatures. Extracted
       from the ``[proto: N/Name]`` field. For layered protocols (e.g.
       ``QUIC.Google``) the rightmost component is used as the app name.
   * - Category
     - Traffic category (e.g. ``Web``, ``VPN``, ``Social Network``,
       ``Malware``). Extracted from the ``[cat: Name/ID]`` field.
   * - Risk flags
     - Per-conversation risk alerts extracted from the
       ``[Risk: ** Name1 **** Name2 **]`` block and normalized to
       ``lowercase_underscore`` form (e.g. ``clear_text_credentials``,
       ``known_protocol_on_non_standard_port``, ``self_signed_certificate``).
   * - JA3C fingerprint
     - Client TLS fingerprint (MD5 hash of TLS ClientHello parameters).
       Extracted from the ``[JA3C: <hash>]`` field.
   * - JA3S fingerprint
     - Server TLS fingerprint (MD5 hash of TLS ServerHello parameters).
       Extracted from the ``[JA3S: <hash>]`` field.
   * - SNI (Server Name Indication)
     - Hostname extracted from TLS ClientHello. Extracted from the
       ``[Hostname/SNI: <host>]`` field.
   * - TLS certificate metadata
     - Subject DN, issuer DN, not-before date, and not-after date. Extracted
       from the ``[Subject: ...]``, ``[Issuer: ...]``, ``[NotBefore: ...]``,
       and ``[NotAfter: ...]`` fields respectively.

Misclassification Corrections
------------------------------

The backend applies post-processing corrections to known nDPI
misclassifications before storing results:

- **UFTP** (UDP port 1044) — misclassified as ``BitTorrent`` by nDPI 5.x
  because binary file-transfer payloads trigger BitTorrent heuristics.
  Corrected to ``UFTP``.
- **H.225** (TCP port 1720) — misclassified as ``Cassandra`` in some nDPI
  builds. Corrected to ``H225``.
- **H.323 sub-protocols** — nDPI reports all H.323 flows as ``H323``.
  Corrected to ``H225`` (TCP port 1720, call signaling) or ``H245`` (other
  TCP ports, media control).

Viewing nDPI Results
--------------------

nDPI data surfaces across multiple views:

- **Overview tab** — summary counts of detected applications, categories,
  and risk alerts.
- **Conversations tab** — per-row columns for Application, Category, Risk,
  JA3C, JA3S, and SNI; filterable by any of these fields.
- **Node Detail Panel** — risk badges on individual host nodes in the network
  graph.

Risk Flags
----------

Risk flags are color-coded badges displayed alongside conversations:

- ``critical`` — red
- ``high`` — orange
- ``medium`` — amber / yellow
- ``low`` — purple

Custom signature rules (see :doc:`custom-signatures`) add additional badges
to these nDPI-native detections.

Enabling nDPI
-------------

nDPI analysis is opt-in per upload. Enable the **nDPI Analysis** toggle in
the upload dialog before submitting the file. It cannot be added after
upload — re-upload the file with the toggle enabled if needed.

Graceful Degradation
--------------------

If ``ndpiReader`` is not installed or fails, all ``appName``, ``flowRisks``,
and related fields remain empty and analysis continues normally with tshark
data only. A warning is logged but no error is surfaced to the user.
