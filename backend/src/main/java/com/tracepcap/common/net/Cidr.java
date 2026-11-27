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
   * in Java's long form ({@code fd00:0:0:0:0:0:0:0/64}), as custom ranges have always been stored.
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
    try {
      return InetAddress.getByAddress(bytes).getHostAddress() + "/" + prefix;
    } catch (Exception e) {
      throw invalid(raw);
    }
  }

  /**
   * The form a stored CIDR is compared and shown in: {@link #normalise}d, or as stored (trimmed)
   * when it isn't a literal CIDR (a row saved before #1351 from free text). Rows saved earlier keep
   * their text in the database ({@code fd00::/8}, {@code 10.1.2.3/8}); comparing and answering in
   * this form makes them the same entry as what a save writes now, with nothing to migrate.
   */
  public static String key(String stored) {
    if (stored == null) return null;
    try {
      return normalise(stored);
    } catch (IllegalArgumentException e) {
      return stored.trim();
    }
  }

  /** Whether two CIDRs, stored or typed, name the same network. */
  public static boolean same(String a, String b) {
    return a != null && b != null && key(a).equals(key(b));
  }

  /** Whether a CIDR {@link #normalise} wrote is IPv4. */
  public static boolean isIpv4(String normalised) {
    return normalised != null && normalised.indexOf(':') < 0;
  }

  private static IllegalArgumentException invalid(String raw) {
    return new IllegalArgumentException("Invalid CIDR: " + raw.trim());
  }
}
