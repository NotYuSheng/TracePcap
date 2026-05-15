package com.lanturn.analysis.service;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.apache.tika.Tika;
import org.apache.tika.mime.MimeType;
import org.apache.tika.mime.MimeTypeException;
import org.apache.tika.mime.MimeTypes;

@Slf4j

/**
 * Detects file types from the leading bytes of a packet's application-layer payload using Apache
 * Tika's magic-byte detection.
 */
public final class FileSignatureDetector {

  private FileSignatureDetector() {}

  private static final Tika TIKA = new Tika();
  private static final MimeTypes TIKA_MIME_REPO = MimeTypes.getDefaultMimeTypes();

  /**
   * Overrides for cases where Tika's primary extension does not match the conventional badge label
   * (e.g. Tika maps image/jpeg to ".jpg" but the badge should read "JPEG").
   */
  private static final Map<String, String> MIME_LABEL_OVERRIDES =
      Map.ofEntries(
          Map.entry("image/jpeg", "JPEG"),
          Map.entry("audio/mpeg", "MP3"),
          Map.entry("audio/ogg", "OGG"),
          Map.entry("application/x-bzip2", "BZIP2"),
          Map.entry("application/x-msdownload", "EXE/DLL"),
          Map.entry("application/x-dosexec", "EXE/DLL"),
          Map.entry("application/x-sharedlib", "ELF"),
          Map.entry("application/x-sqlite3", "SQLITE"));

  /**
   * If {@code bytes} begins with an HTTP response status line ({@code HTTP/}), returns the bytes
   * after the header block ({@code \r\n\r\n}). Returns the original array unchanged for all other
   * payloads, or {@code null} if the payload contains only headers with no body.
   */
  static byte[] skipHttpResponseHeaders(byte[] bytes) {
    if (bytes.length < 5
        || bytes[0] != 'H'
        || bytes[1] != 'T'
        || bytes[2] != 'T'
        || bytes[3] != 'P'
        || bytes[4] != '/') {
      return bytes;
    }
    for (int i = 0; i < bytes.length - 3; i++) {
      if (bytes[i] == '\r'
          && bytes[i + 1] == '\n'
          && bytes[i + 2] == '\r'
          && bytes[i + 3] == '\n') {
        int bodyStart = i + 4;
        return bodyStart < bytes.length ? Arrays.copyOfRange(bytes, bodyStart, bytes.length) : null;
      }
    }
    return null; // headers present but no body within the captured window
  }

  /**
   * Returns a short human-readable label (e.g. {@code "PDF"}, {@code "EXE/DLL"}) for the file type
   * detected from {@code appLayerBytes}, or {@code null} if the type is unknown or unrecognised.
   *
   * @param appLayerBytes raw bytes of the application-layer payload (may be null or empty)
   */
  public static String detect(byte[] appLayerBytes) {
    if (appLayerBytes == null || appLayerBytes.length == 0) return null;
    try {
      byte[] bytesToDetect = skipHttpResponseHeaders(appLayerBytes);
      if (bytesToDetect == null || bytesToDetect.length == 0) return null;
      String mime = TIKA.detect(new ByteArrayInputStream(bytesToDetect));
      if (mime == null
          || mime.equals("application/octet-stream")
          || mime.equals("text/plain")
          || mime.equals("application/x-www-form-urlencoded")) {
        return null;
      }
      return labelFromMime(mime);
    } catch (Exception e) {
      log.warn("File signature detection failed", e);
      return null;
    }
  }

  static String labelFromMime(String mime) {
    String override = MIME_LABEL_OVERRIDES.get(mime);
    if (override != null) return override;
    try {
      MimeType mt = TIKA_MIME_REPO.forName(mime);
      String ext = mt.getExtension(); // e.g. ".pdf", ".docx"
      if (ext != null && ext.length() > 1) {
        return ext.substring(1).toUpperCase(); // strip leading dot
      }
    } catch (MimeTypeException ignored) {
    }
    // Fallback: derive from subtype string
    String subtype = mime.contains("/") ? mime.substring(mime.indexOf('/') + 1) : mime;
    subtype = subtype.replaceAll("^(x-|vnd\\.)", "").toUpperCase();
    return (!subtype.isEmpty() && subtype.length() <= 12) ? subtype : null;
  }
}
