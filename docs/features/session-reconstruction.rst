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

STUN Decoder
------------

When a conversation is identified as STUN (by nDPI, tshark metadata, the
magic cookie ``0x2112A442``, or port heuristics — 3478/5349), a
**STUN Messages** tab appears in the session toolbar alongside Raw Stream.
It is selected automatically on load when STUN messages are present.

Decoded fields include:

- Message type and class (e.g. Binding Request, Binding Success Response,
  Allocate Request).
- Transaction ID.
- Attributes: ``XOR-MAPPED-ADDRESS`` (with XOR un-masking applied),
  ``MAPPED-ADDRESS``, ``USERNAME``, ``SOFTWARE``, ``ERROR-CODE``,
  ``PRIORITY``, ``FINGERPRINT``, and ICE credentials.

Both bare UDP datagrams and TCP-framed STUN (RFC 4571 two-byte length
prefix) are supported.

Media Detection Panel
---------------------

When the stream payload matches a known media signature, a
**MediaInfo** panel appears above the raw/parsed view showing:

- **Type** — ``AUDIO``, ``VIDEO``, or ``IMAGE``.
- **Container** — detected container format (e.g. ``RTP``, ``MP4``,
  ``WebM``, ``Ogg``, ``MPEG-TS``, ``JPEG``, ``PNG``, ``WebP``).
- **Codec** — codec name where detectable.
- **Sample rate** — for audio streams where extractable.

Detected signatures include: RTP (audio/video), MP4, WebM, Ogg, JPEG, PNG,
WebP, AAC, FLAC, MP3, and MPEG-TS.

Limitations
-----------

- Encrypted payloads (TLS, DTLS, etc.) cannot be decrypted without the
  private key. The raw ciphertext is shown instead.
- Highly fragmented or severely out-of-order streams may show incomplete
  results.
