package com.tracepcap.common;

/** Utility methods for handling hex strings produced by tshark field output. */
public final class TsharkHexUtil {

  private TsharkHexUtil() {}

  /**
   * Strip colon separators from a tshark hex field (e.g. {@code "48:54:54:50"} → {@code "485454550"}),
   * lowercase the result, and truncate to {@code maxBytes} bytes.
   * Returns {@code null} if the input is null or empty.
   */
  public static String toHex(String tsharkHex, int maxBytes) {
    if (tsharkHex == null || tsharkHex.isEmpty()) return null;
    String plain = tsharkHex.replace(":", "").toLowerCase();
    int maxChars = maxBytes * 2;
    return plain.length() > maxChars ? plain.substring(0, maxChars) : plain;
  }

  /**
   * Decode a plain lowercase hex string (no colons) to a byte array.
   * Returns {@code null} if the input is null or empty.
   * An incomplete trailing nibble is silently dropped.
   */
  public static byte[] toBytes(String hex) {
    if (hex == null || hex.isEmpty()) return null;
    int len = hex.length();
    if (len % 2 != 0) len--; // drop incomplete trailing nibble
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
          | Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }

  /**
   * Convert a tshark colon-separated hex field to a printable ASCII string, replacing
   * non-printable bytes with {@code '.'}, limited to {@code maxBytes} bytes.
   * Returns an empty string if the input is null or empty.
   */
  public static String toAscii(String tsharkHex, int maxBytes) {
    if (tsharkHex == null || tsharkHex.isEmpty()) return "";
    String plain = tsharkHex.replace(":", "");
    int len = plain.length();
    if (len % 2 != 0) len--; // drop incomplete trailing nibble
    int byteCount = Math.min(len / 2, maxBytes);
    StringBuilder sb = new StringBuilder(byteCount);
    for (int i = 0; i < byteCount * 2; i += 2) {
      int b = (Character.digit(plain.charAt(i), 16) << 4)
          | Character.digit(plain.charAt(i + 1), 16);
      sb.append((b >= 0x20 && b <= 0x7e) ? (char) b : '.');
    }
    return sb.toString();
  }
}
