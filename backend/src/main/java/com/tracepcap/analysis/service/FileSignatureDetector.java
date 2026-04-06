package com.tracepcap.analysis.service;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.apache.tika.Tika;

@Slf4j

/**
 * Detects file types from the leading bytes of a packet's application-layer payload using Apache
 * Tika's magic-byte detection.
 */
public final class FileSignatureDetector {

  private FileSignatureDetector() {}

  private static final Tika TIKA = new Tika();

  /** Maps Tika MIME types to short human-readable badge labels. */
  private static final Map<String, String> MIME_LABELS =
      Map.ofEntries(
          // Archives
          Map.entry("application/zip", "ZIP"),
          Map.entry("application/x-7z-compressed", "7-ZIP"),
          Map.entry("application/x-rar-compressed", "RAR"),
          Map.entry("application/x-gzip", "GZIP"),
          Map.entry("application/gzip", "GZIP"),
          Map.entry("application/x-bzip2", "BZIP2"),
          Map.entry("application/x-xz", "XZ"),
          Map.entry("application/x-tar", "TAR"),
          // Executables
          Map.entry("application/x-msdownload", "EXE/DLL"),
          Map.entry("application/x-dosexec", "EXE/DLL"),
          Map.entry("application/x-elf", "ELF"),
          Map.entry("application/java-vm", "CLASS"),
          Map.entry("application/x-sharedlib", "ELF"),
          // Documents
          Map.entry("application/pdf", "PDF"),
          Map.entry("application/msword", "DOC"),
          Map.entry("application/vnd.ms-excel", "XLS"),
          Map.entry("application/vnd.ms-powerpoint", "PPT"),
          Map.entry(
              "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "DOCX"),
          Map.entry("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "XLSX"),
          Map.entry(
              "application/vnd.openxmlformats-officedocument.presentationml.presentation", "PPTX"),
          Map.entry("application/vnd.oasis.opendocument.text", "ODT"),
          Map.entry("application/vnd.oasis.opendocument.spreadsheet", "ODS"),
          // Images
          Map.entry("image/png", "PNG"),
          Map.entry("image/jpeg", "JPEG"),
          Map.entry("image/gif", "GIF"),
          Map.entry("image/bmp", "BMP"),
          Map.entry("image/tiff", "TIFF"),
          Map.entry("image/webp", "WEBP"),
          Map.entry("image/vnd.adobe.photoshop", "PSD"),
          // Audio / Video
          Map.entry("audio/mpeg", "MP3"),
          Map.entry("audio/ogg", "OGG"),
          Map.entry("audio/x-flac", "FLAC"),
          Map.entry("audio/flac", "FLAC"),
          Map.entry("audio/wav", "WAV"),
          Map.entry("video/mp4", "MP4"),
          Map.entry("video/x-msvideo", "AVI"),
          Map.entry("video/quicktime", "MOV"),
          Map.entry("video/x-matroska", "MKV"),
          // Database
          Map.entry("application/x-sqlite3", "SQLITE"),
          // Java
          Map.entry("application/java-archive", "JAR"));

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
      String label = MIME_LABELS.get(mime);
      // Fall back to a tidied version of the subtype if no explicit mapping exists
      if (label == null) {
        String subtype = mime.contains("/") ? mime.substring(mime.indexOf('/') + 1) : mime;
        subtype = subtype.replaceAll("^(x-|vnd\\.)", "").toUpperCase();
        label = subtype.length() <= 12 ? subtype : null;
      }
      return label;
    } catch (Exception e) {
      log.warn("File signature detection failed", e);
      return null;
    }
  }
}
