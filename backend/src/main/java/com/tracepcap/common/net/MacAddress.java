package com.tracepcap.common.net;

/**
 * The one definition of "are these two MAC addresses the same" (#733).
 *
 * <p>Three normalisations existed before this: {@code PcapParserService} lowercased at parse time,
 * {@code DeviceClassifierService.ouiKey} lowercased <em>and</em> mapped {@code -}/{@code .} to
 * {@code :}, and {@code ChangeDetectionService} lowercased only. Whichever a comparison happened to
 * use decided whether two spellings of one address matched.
 *
 * <p>That is not a cosmetic difference. An operator who typed {@code AA-BB-CC-DD-EE-FF} into the
 * baseline panel had it stored verbatim and compared against a colon-form capture, so a device that
 * was present in every snapshot was reported missing from every snapshot — and an alert that fires
 * on a healthy network is how an operator learns to ignore the queue.
 *
 * <p>Deliberately not a validator. Callers hold operator-typed text and capture output, and
 * rejecting an odd-looking address here would turn a comparison into a failure. Anything
 * unrecognisable is returned trimmed and lowercased so it can still compare equal to itself.
 */
public final class MacAddress {

  private MacAddress() {}

  /**
   * Canonical lower-case colon form, e.g. {@code "aa:bb:cc:dd:ee:ff"}.
   *
   * <p>Accepts colon, hyphen and dot separators, Cisco {@code aabb.ccdd.eeff} triplets, and bare
   * hex. Returns {@code null} for null/blank input so callers can treat "no MAC" distinctly from
   * "a MAC that normalises to nothing".
   */
  public static String normalise(String mac) {
    if (mac == null) return null;
    String trimmed = mac.trim();
    if (trimmed.isEmpty()) return null;

    String hex = trimmed.toLowerCase().replace("-", "").replace(":", "").replace(".", "");
    // Only regroup when the result is exactly a 48-bit address in hex. Anything else keeps its
    // separators rather than being silently reshaped into something that looks canonical.
    if (hex.length() != 12 || !isHex(hex)) {
      return trimmed.toLowerCase();
    }

    StringBuilder out = new StringBuilder(17);
    for (int i = 0; i < 12; i += 2) {
      if (i > 0) out.append(':');
      out.append(hex, i, i + 2);
    }
    return out.toString();
  }

  /** Whether two addresses denote the same hardware, ignoring case and separator style. */
  public static boolean sameAddress(String a, String b) {
    String na = normalise(a);
    String nb = normalise(b);
    return na != null && na.equals(nb);
  }

  /**
   * The vendor prefix as {@code "aa:bb:cc"}, or {@code null} if the address is too short to have
   * one. Kept here rather than in the classifier so the OUI lookup and the comparison agree.
   */
  public static String oui(String mac) {
    String normalised = normalise(mac);
    if (normalised == null) return null;
    String hex = normalised.replace(":", "");
    if (hex.length() < 6 || !isHex(hex)) return null;
    return hex.substring(0, 2) + ":" + hex.substring(2, 4) + ":" + hex.substring(4, 6);
  }

  private static boolean isHex(String s) {
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      boolean hexDigit = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
      if (!hexDigit) return false;
    }
    return true;
  }
}
