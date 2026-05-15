Session Reconstruction
======================

Session Reconstruction decodes the application-layer payload of a TCP or UDP
conversation and presents it in a side-by-side **hex + ASCII viewer**.

Opening the Viewer
------------------

From the **Conversations** tab, click the eye icon on any conversation row.
A panel slides in showing the reconstructed payload.

Hex + ASCII Viewer
------------------

The viewer displays payload bytes in two columns:

- **Hex** — raw bytes in hexadecimal, 16 bytes per row.
- **ASCII** — printable ASCII representation of the same bytes; non-printable
  bytes are shown as ``.``.

Clicking a byte in either column highlights the corresponding byte in the
other column.

Payload Decompression
---------------------

If the payload is gzip- or deflate-compressed (e.g. HTTP responses with
``Content-Encoding: gzip``), TracePcap automatically decompresses it before
display so you see the plaintext content.

Stream Direction
----------------

The viewer color-codes bytes by direction:

- **Blue** — client-to-server bytes.
- **Green** — server-to-client bytes.

Limitations
-----------

- Encrypted payloads (TLS, DTLS, etc.) cannot be decrypted without the
  private key. The raw ciphertext is shown instead.
- Fragmented IP packets are reassembled where possible; highly fragmented or
  out-of-order streams may show gaps.
- Very large payloads (>10 MB per stream) are truncated to protect browser
  performance.
