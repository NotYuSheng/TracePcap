package com.tracepcap.subnets.service;

/** Small shared helpers for IPv4 CIDR range maths, used by the subnet services. */
final class CidrRange {

  private CidrRange() {}

  /** Inclusive {@code [network, broadcast]} integer range for an IPv4 CIDR (e.g. "10.0.1.0/24"). */
  static long[] of(String cidr) {
    String[] parts = cidr.split("/");
    long base = ipToLong(parts[0]);
    int prefix = Integer.parseInt(parts[1]);
    long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
    long network = base & mask;
    long broadcast = network | (~mask & 0xFFFFFFFFL);
    return new long[] {network, broadcast};
  }

  /** Dotted-quad IPv4 string to its 32-bit integer value. */
  static long ipToLong(String ip) {
    String[] o = ip.split("\\.");
    long v = 0;
    for (String part : o) v = (v << 8) | Integer.parseInt(part);
    return v;
  }
}
