package com.tracepcap.common.net;

import java.net.InetAddress;
import java.util.regex.Pattern;

/**
 * A CIDR an operator types into a settings list (subnet labels, internal/external ranges), checked
 * and written one way (#1351). Two services used to do this differently: one kept {@code
 * 10.1.2.3/8} as typed and refused IPv6 and bare addresses, the other turned a bare address into
 * {@code /32} and kept host bits, so the same input meant different things in two lists.
 */
public final class Cidr {

  private Cidr() {}

  private static final Pattern IPV4 =
      Pattern.compile("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");

  /** Hex, colons and an optional dotted tail: an IPv6 literal, never a name to resolve. */
  private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:]*:[0-9a-fA-F:.]*$");

  /**
   * {@code "10.0.0.0/8"} from {@code " 10.1.2.3/8 "}: trimmed, a bare address made {@code /32} (or
   * {@code /128}), and the host bits zeroed so the entry is the network it names. IPv6 comes back
   * in RFC 5952 form ({@code fd00::/64}).
   * Literals only: nothing here resolves a name.
   *
   * @throws IllegalArgumentException "A CIDR is required" when blank, "Invalid CIDR: …" otherwise
   */
  public static String normalise(String raw) {
    if (raw == null || raw.isBlank()) throw new IllegalArgumentException("A CIDR is required");
    String cidr = raw.trim();
    int slash = cidr.indexOf('/');
    String address = (slash < 0 ? cidr : cidr.substring(0, slash)).trim();
    boolean v4 = IPV4.matcher(address).matches();
    if (!v4 && !IPV6.matcher(address).matches()) throw invalid(raw);
    byte[] bytes;
    try {
      bytes = InetAddress.getByName(address).getAddress();
    } catch (Exception e) {
      throw invalid(raw);
    }
    if (v4 != (bytes.length == 4)) throw invalid(raw); // an IPv4-mapped IPv6 literal, say
    int max = bytes.length * 8;
    int prefix;
    if (slash < 0) {
      prefix = max;
    } else {
      String p = cidr.substring(slash + 1).trim();
      if (!p.matches("\\d{1,3}")) throw invalid(raw);
      prefix = Integer.parseInt(p);
      if (prefix > max) throw invalid(raw);
    }
    for (int i = 0; i < bytes.length; i++) {
      int keep = Math.max(0, Math.min(8, prefix - i * 8));
      bytes[i] &= (byte) (0xFF << (8 - keep));
    }
    return (bytes.length == 4 ? v4(bytes) : v6(bytes)) + "/" + prefix;
  }

  /**
   * {@link #normalise}, for a list that is IPv4 only for now: subnet labels and their per-snapshot
   * overrides. Subnet matching (subnets' CidrRange, the frontend's ipInCidr) is IPv4 arithmetic, so
   * an IPv6 entry would save and never match (#1354).
   */
  public static String normaliseIpv4(String raw) {
    String cidr = normalise(raw);
    if (!isIpv4(cidr)) throw new IllegalArgumentException("Subnet labels are IPv4 for now: " + raw.trim());
    return cidr;
  }

  /**
   * {@code raw} as already saved, when it is exactly one of {@code saved}; otherwise {@code
   * normaliser}'s answer. A list answers with what it stores, and V86 leaves a few rows in their
   * old spelling (two spellings of one network, or text the parser refuses), so an entry sent back
   * exactly as listed (to hide, edit or carry it) is the same entry, not refused or re-spelled.
   * Anything new is normalised.
   */
  public static String asSaved(
      String raw, java.util.Collection<String> saved, java.util.function.UnaryOperator<String> normaliser) {
    if (raw != null && saved != null && saved.contains(raw.trim())) return raw.trim();
    return normaliser.apply(raw);
  }

  /**
   * The form a stored CIDR is written in: {@link #normalise}d, or as stored (trimmed) when it isn't
   * a literal CIDR (free text an older validator let through). For moving rows saved before #1351
   * onto what a save writes now (V86).
   */
  public static String key(String stored) {
    if (stored == null) return null;
    try {
      return normalise(stored);
    } catch (IllegalArgumentException e) {
      return stored.trim();
    }
  }

  private static String v4(byte[] b) {
    return (b[0] & 0xFF) + "." + (b[1] & 0xFF) + "." + (b[2] & 0xFF) + "." + (b[3] & 0xFF);
  }

  /**
   * RFC 5952: lowercase hex without leading zeros, the longest run of two or more zero groups (the
   * first, on a tie) as {@code ::}. What an operator types ({@code fd00::}), not Java's long form.
   */
  private static String v6(byte[] b) {
    int[] g = new int[8];
    for (int i = 0; i < 8; i++) g[i] = ((b[2 * i] & 0xFF) << 8) | (b[2 * i + 1] & 0xFF);
    int bestStart = -1, bestLen = 0;
    for (int i = 0; i < 8; ) {
      if (g[i] != 0) { i++; continue; }
      int j = i;
      while (j < 8 && g[j] == 0) j++;
      if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
      i = j;
    }
    if (bestLen < 2) bestStart = -1;
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < 8; i++) {
      if (i == bestStart) {
        out.append("::");
        i += bestLen - 1;
        continue;
      }
      if (out.length() > 0 && out.charAt(out.length() - 1) != ':') out.append(':');
      out.append(Integer.toHexString(g[i]));
    }
    return out.toString();
  }

  /** Whether a CIDR {@link #normalise} wrote is IPv4. */
  public static boolean isIpv4(String normalised) {
    return normalised != null && normalised.indexOf(':') < 0;
  }

  private static IllegalArgumentException invalid(String raw) {
    return new IllegalArgumentException("Invalid CIDR: " + raw.trim());
  }
}
