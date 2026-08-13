package com.tracepcap.common.net;

/**
 * The single answer to "is this address local rather than routable on the public internet".
 *
 * <p>Four services used to answer this independently and disagreed (#694). The same host could be
 * internal on one code path and external on another, which changes how a capture is summarised
 * depending on which path produced the summary. That divergence was invisible in any one file.
 *
 * <p><b>Ranges are parsed, not prefix-matched.</b> Every previous implementation compared the
 * address as text, which is only correct where a range boundary happens to land on a digit
 * boundary. {@code fe80::/10} spans {@code fe80::} to {@code febf::}, so a {@code "fe80"} string
 * prefix matched a sixteenth of it and reported {@code febf::1} — link-local — as public.
 *
 * <p>Loopback and link-local count as local. They are not routable off-host or off-link, so
 * treating them as external puts addresses in the "talking to the outside world" bucket that by
 * definition cannot. The old implementations disagreed on both.
 */
public final class IpLocality {

  private IpLocality() {}

  private record V4Range(long network, long broadcast) {
    boolean contains(long ip) {
      return ip >= network && ip <= broadcast;
    }
  }

  /** RFC1918 private use, loopback, and RFC3927 link-local. */
  private static final V4Range[] LOCAL_V4 = {
    range("10.0.0.0", 8), // RFC1918
    range("172.16.0.0", 12), // RFC1918
    range("192.168.0.0", 16), // RFC1918
    range("127.0.0.0", 8), // loopback
    range("169.254.0.0", 16), // link-local (RFC3927)
  };

  /**
   * True when the address is loopback, link-local, or private/unique-local — anything not
   * routable on the public internet.
   *
   * <p>A null, blank or unparseable address is <b>not</b> local. Three of the four old
   * implementations already agreed on that; the fourth treated null as local, which silently
   * counted rows with no address as internal traffic.
   */
  public static boolean isLocal(String ip) {
    if (ip == null) {
      return false;
    }
    String addr = ip.trim();
    if (addr.isEmpty()) {
      return false;
    }
    return addr.indexOf(':') >= 0 ? isLocalV6(addr) : isLocalV4(addr);
  }

  private static boolean isLocalV4(String ip) {
    long value;
    try {
      value = toLong(ip);
    } catch (RuntimeException e) {
      return false; // not a dotted quad — cannot be classified, so not claimed as local
    }
    for (V4Range r : LOCAL_V4) {
      if (r.contains(value)) {
        return true;
      }
    }
    return false;
  }

  /**
   * IPv6 by first hextet, which is enough for the three ranges that matter and avoids a full
   * address parser. {@code ::1} is loopback; {@code fc00::/7} is unique-local; {@code fe80::/10}
   * is link-local — and that last one is why the first hextet is compared as a <em>number</em>
   * rather than a string, since it spans fe80 through febf.
   */
  private static boolean isLocalV6(String ip) {
    String addr = ip.toLowerCase();
    int zone = addr.indexOf('%'); // strip a scope id such as fe80::1%eth0
    if (zone >= 0) {
      addr = addr.substring(0, zone);
    }
    if (addr.equals("::1")) {
      return true;
    }
    int hextet;
    try {
      hextet = Integer.parseInt(firstHextet(addr), 16);
    } catch (RuntimeException e) {
      return false;
    }
    boolean uniqueLocal = hextet >= 0xfc00 && hextet <= 0xfdff; // fc00::/7
    boolean linkLocal = hextet >= 0xfe80 && hextet <= 0xfebf; // fe80::/10
    return uniqueLocal || linkLocal;
  }

  private static String firstHextet(String addr) {
    int end = addr.indexOf(':');
    String first = end < 0 ? addr : addr.substring(0, end);
    if (first.isEmpty() || first.length() > 4) {
      throw new IllegalArgumentException("not a hextet: " + first);
    }
    return first;
  }

  private static V4Range range(String base, int prefix) {
    long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
    long network = toLong(base) & mask;
    return new V4Range(network, network | (~mask & 0xFFFFFFFFL));
  }

  private static long toLong(String ip) {
    String[] octets = ip.split("\\.");
    if (octets.length != 4) {
      throw new IllegalArgumentException("not a dotted quad: " + ip);
    }
    long value = 0;
    for (String octet : octets) {
      int part = Integer.parseInt(octet);
      if (part < 0 || part > 255) {
        throw new IllegalArgumentException("octet out of range: " + ip);
      }
      value = (value << 8) | part;
    }
    return value;
  }
}
