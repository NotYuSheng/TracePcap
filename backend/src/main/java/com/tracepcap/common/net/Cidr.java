package com.tracepcap.common.net;

import java.net.InetAddress;
import java.util.regex.Pattern;

/**
 * A CIDR an operator types into a settings list (subnet labels, internal/external ranges,
 * organisation rules), checked and written one way (#1351). {@link CidrBlock} reads a saved one
 * and answers what is inside it (#1354). Two services used to do this differently: one kept {@code
 * 10.1.2.3/8} as typed and refused IPv6 and bare addresses, the other turned a bare address into
 * {@code /32} and kept host bits, so the same input meant different things in two lists.
 */
public final class Cidr {

  private Cidr() {}

  private static final Pattern IPV4 =
      Pattern.compile("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");

  private static final Pattern LOOSE_IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

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
    byte[] bytes = addressBytes(address);
    if (bytes == null) throw invalid(raw);
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
    return formatAddress(CidrBlock.mask(bytes, prefix)) + "/" + prefix;
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
    boolean mapped = true;
    for (int i = 0; i < 10; i++) mapped &= b[i] == 0;
    if (mapped && (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF) {
      // RFC 5952 §5: an IPv4-mapped address keeps its dotted tail, as tshark writes it.
      return "::ffff:" + v4(java.util.Arrays.copyOfRange(b, 12, 16));
    }
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

  /**
   * The bytes of an address literal (4 for IPv4, 16 for IPv6), or null for anything else: a name, a
   * MAC endpoint, a CIDR. Never a DNS lookup. A scope id ({@code fe80::1%eth0}) is dropped, and
   * an older spelling with leading zeros ({@code 10.0.0.01}) still reads, for rows saved before
   * {@link #normalise}. An IPv4-mapped IPv6 address reads as its IPv4 address, as {@code
   * InetAddress} reads it.
   */
  public static byte[] addressBytes(String ip) {
    if (ip == null) return null;
    String a = ip.trim();
    int zone = a.indexOf('%');
    if (zone >= 0) a = a.substring(0, zone);
    if (a.isEmpty()) return null;
    if (a.indexOf(':') < 0) {
      // Four dotted parts only: InetAddress also reads "10.1" (as 10.0.0.1), which isn't an address
      // anyone wrote.
      if (!LOOSE_IPV4.matcher(a).matches()) return null;
      String[] o = a.split("\\.");
      byte[] b = new byte[4];
      for (int i = 0; i < 4; i++) {
        int v = Integer.parseInt(o[i]);
        if (v > 255) return null;
        b[i] = (byte) v;
      }
      return b;
    }
    if (!IPV6.matcher(a).matches()) return null;
    try {
      return InetAddress.getByName(a).getAddress(); // a literal by the check above, so no lookup
    } catch (Exception e) {
      return null;
    }
  }

  /** {@code 10.0.0.1}, or IPv6 in RFC 5952 form ({@code fd00::1}): how an address is written. */
  public static String formatAddress(byte[] b) {
    return b.length == 4 ? v4(b) : v6(b);
  }

  /**
   * Addresses in order of value: IPv4, then IPv6, then anything else (a name, a MAC) as text. How
   * tables and lists of addresses sort.
   */
  public static final java.util.Comparator<String> ADDRESS_ORDER =
      java.util.Comparator.comparing(Cidr::sortKey);

  /** The key {@link #ADDRESS_ORDER} sorts by. */
  public static String sortKey(String ip) {
    if (ip == null) return "";
    byte[] b = addressBytes(ip);
    if (b == null) return "~" + ip;
    StringBuilder sb = new StringBuilder(b.length == 4 ? "4" : "6");
    for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
    return sb.toString();
  }

  private static IllegalArgumentException invalid(String raw) {
    return new IllegalArgumentException("Invalid CIDR: " + raw.trim());
  }
}
