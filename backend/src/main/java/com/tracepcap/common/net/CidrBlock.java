package com.tracepcap.common.net;

import java.util.Arrays;
import java.util.Optional;

/**
 * A parsed CIDR, IPv4 or IPv6, and the one answer to "is this address inside it" (#1354). Five
 * classes used to work this out themselves: three compared bytes, two did IPv4 arithmetic on a
 * {@code long} and so never matched an IPv6 address.
 *
 * <p>Reading is lenient, because it reads rows as they were saved: a bare address is a single host,
 * host bits are dropped, and an older spelling such as {@code 10.0.0.01/24} still parses. Literals
 * only, so nothing here ever resolves a name. To check what an operator types, use {@link
 * Cidr#normalise}.
 */
public final class CidrBlock {

  private final byte[] network;
  private final int prefix;

  private CidrBlock(byte[] network, int prefix) {
    this.network = network;
    this.prefix = prefix;
  }

  /** The block {@code cidr} names, or empty when it isn't a literal CIDR. */
  public static Optional<CidrBlock> parse(String cidr) {
    if (cidr == null) return Optional.empty();
    String s = cidr.trim();
    int slash = s.indexOf('/');
    byte[] bytes = Cidr.addressBytes(slash < 0 ? s : s.substring(0, slash));
    if (bytes == null) return Optional.empty();
    // An IPv4-mapped network (::ffff:0:0/96) reads as IPv4, as its addresses do: /96 is 0.0.0.0/0.
    boolean mapped = bytes.length == 4 && s.indexOf(':') >= 0 && s.indexOf(':') < (slash < 0 ? s.length() : slash);
    int max = bytes.length * 8;
    int prefix = max;
    if (slash >= 0) {
      String p = s.substring(slash + 1).trim();
      if (!p.matches("\\d{1,3}")) return Optional.empty();
      prefix = Integer.parseInt(p) - (mapped ? 96 : 0);
      if (prefix < 0 || prefix > max) return Optional.empty();
    }
    return Optional.of(new CidrBlock(mask(bytes, prefix), prefix));
  }

  /** Saved CIDRs read once each: a list is matched against every address in a capture. */
  private static final java.util.Map<String, Optional<CidrBlock>> READ =
      new java.util.concurrent.ConcurrentHashMap<>();

  /**
   * Whether {@code ip} is inside {@code cidr}, a saved CIDR: the one way to ask (#1354). False when
   * either isn't a literal. The parsed CIDR is remembered, so call it in a loop freely.
   */
  public static boolean contains(String cidr, String ip) {
    return contains(cidr, Cidr.addressBytes(ip));
  }

  /** {@link #contains(String, String)} for an address already read, to match one against a list. */
  public static boolean contains(String cidr, byte[] address) {
    if (cidr == null || address == null) return false;
    if (READ.size() > 4096) READ.clear(); // bounded: settings lists are small, rule text is not ours
    Optional<CidrBlock> b = READ.computeIfAbsent(cidr, CidrBlock::parse);
    return b.isPresent() && b.get().contains(address);
  }

  /** Whether {@code ip}, an address literal, is inside the block. False for anything else. */
  public boolean contains(String ip) {
    byte[] a = Cidr.addressBytes(ip);
    return a != null && contains(a);
  }

  /** Whether an address (4 or 16 bytes) is inside the block. Another family is never inside. */
  public boolean contains(byte[] address) {
    if (address == null || address.length != network.length) return false;
    int full = prefix / 8;
    for (int i = 0; i < full; i++) if (address[i] != network[i]) return false;
    int rest = prefix % 8;
    if (rest == 0) return true;
    int m = 0xFF << (8 - rest);
    return (address[full] & m) == (network[full] & m);
  }

  public int prefix() {
    return prefix;
  }

  public boolean isIpv4() {
    return network.length == 4;
  }

  /** {@code 10.0.0.0/8}, {@code fd00::/8}: the form {@link Cidr#normalise} writes. */
  @Override
  public String toString() {
    return Cidr.formatAddress(network) + "/" + prefix;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof CidrBlock b && prefix == b.prefix && Arrays.equals(network, b.network);
  }

  @Override
  public int hashCode() {
    return 31 * Arrays.hashCode(network) + prefix;
  }

  static byte[] mask(byte[] bytes, int prefix) {
    byte[] out = bytes.clone();
    for (int i = 0; i < out.length; i++) {
      int keep = Math.max(0, Math.min(8, prefix - i * 8));
      out[i] &= (byte) (0xFF << (8 - keep));
    }
    return out;
  }
}
