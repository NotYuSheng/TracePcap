Session Reconstruction
======================

Session Reconstruction decodes the application-layer payload of a TCP or UDP
conversation using ``tshark`` and presents the result in the UI.

How It Works
------------

1. The backend runs ``tshark -q -z follow,<proto>,raw,<N>`` to extract the
   raw byte stream for a given conversation (where ``<proto>`` is ``tcp`` or
   ``udp`` and ``<N>`` is the tshark stream index). Both directions are tried
   automatically to locate the correct stream.
2. The hex-encoded output chunks are decoded to bytes and tagged with their
   direction — **Node 0** (client → server) or **Node 1** (server → client).
3. Each chunk is passed through protocol-aware parsers (HTTP, TLS, DNS, RTP,
   etc.) to extract structured fields where possible.
4. The result is returned to the frontend as an ordered list of typed chunks
   with direction metadata for display.

Opening the Viewer
------------------

From the **Conversations** tab, click the eye icon on any conversation row.
A panel slides in showing the reconstructed payload.

Payload Decompression
---------------------

If an HTTP response carries a ``Content-Encoding: gzip`` or
``Content-Encoding: deflate`` header, TracePcap automatically decompresses
the body before display. Both zlib-wrapped deflate (RFC 7230) and raw deflate
are supported, with automatic fallback between the two.

Stream Direction
----------------

Bytes are color-coded by direction:

- **Blue** — client-to-server (Node 0).
- **Green** — server-to-client (Node 1).

Truncation Limits
-----------------

- Maximum stream size: **1 MB** per reconstruction. Streams larger than this
  are truncated.
- Maximum HTTP response body displayed: **64 KB**.
- PCAP files larger than **500 MB** are excluded from session reconstruction
  to protect disk I/O.

Limitations
-----------

- Encrypted payloads (TLS, DTLS, etc.) cannot be decrypted without the
  private key. The raw ciphertext is shown instead.
- Highly fragmented or severely out-of-order streams may show incomplete
  results.
