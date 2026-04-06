package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class FileSignatureDetectorTest {

  // JPEG magic bytes: FF D8 FF E0
  private static final byte[] JPEG_MAGIC = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0};

  // PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
  private static final byte[] PNG_MAGIC = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

  private static byte[] httpResponse(String headers, byte[] body) {
    byte[] headerBytes = headers.getBytes(StandardCharsets.US_ASCII);
    byte[] result = new byte[headerBytes.length + body.length];
    System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
    System.arraycopy(body, 0, result, headerBytes.length, body.length);
    return result;
  }

  // --- skipHttpResponseHeaders ---

  @Test
  void skipHttpResponseHeaders_nonHttp_returnsOriginal() {
    byte[] input = JPEG_MAGIC;
    assertThat(FileSignatureDetector.skipHttpResponseHeaders(input)).isSameAs(input);
  }

  @Test
  void skipHttpResponseHeaders_httpWithBody_returnsBodyOnly() {
    String headers = "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n";
    byte[] payload = httpResponse(headers, JPEG_MAGIC);

    byte[] result = FileSignatureDetector.skipHttpResponseHeaders(payload);

    assertThat(result).startsWith(JPEG_MAGIC);
  }

  @Test
  void skipHttpResponseHeaders_httpHeadersOnly_returnsNull() {
    byte[] payload =
        "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

    assertThat(FileSignatureDetector.skipHttpResponseHeaders(payload)).isNull();
  }

  @Test
  void skipHttpResponseHeaders_httpNoTerminator_returnsNull() {
    byte[] payload =
        "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n".getBytes(StandardCharsets.ISO_8859_1);

    assertThat(FileSignatureDetector.skipHttpResponseHeaders(payload)).isNull();
  }

  // --- detect: JPEG inside HTTP response ---

  @Test
  void detect_jpegDirectBytes_returnsJpeg() {
    // Pad to give Tika enough bytes
    byte[] payload = new byte[64];
    System.arraycopy(JPEG_MAGIC, 0, payload, 0, JPEG_MAGIC.length);

    assertThat(FileSignatureDetector.detect(payload)).isEqualTo("JPEG");
  }

  @Test
  void detect_jpegInsideHttpResponse_returnsJpeg() {
    String headers = "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n";
    byte[] body = new byte[64];
    System.arraycopy(JPEG_MAGIC, 0, body, 0, JPEG_MAGIC.length);
    byte[] payload = httpResponse(headers, body);

    assertThat(FileSignatureDetector.detect(payload)).isEqualTo("JPEG");
  }

  @Test
  void detect_pngInsideHttpResponse_returnsPng() {
    String headers = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n";
    byte[] body = new byte[64];
    System.arraycopy(PNG_MAGIC, 0, body, 0, PNG_MAGIC.length);
    byte[] payload = httpResponse(headers, body);

    assertThat(FileSignatureDetector.detect(payload)).isEqualTo("PNG");
  }

  @Test
  void detect_httpResponseHeadersOnly_returnsNull() {
    byte[] payload =
        "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

    assertThat(FileSignatureDetector.detect(payload)).isNull();
  }

  @Test
  void detect_nullInput_returnsNull() {
    assertThat(FileSignatureDetector.detect(null)).isNull();
  }

  @Test
  void detect_emptyInput_returnsNull() {
    assertThat(FileSignatureDetector.detect(new byte[0])).isNull();
  }
}
