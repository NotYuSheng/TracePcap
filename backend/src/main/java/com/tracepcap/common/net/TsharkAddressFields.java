package com.tracepcap.common.net;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Reading a packet's addresses from tshark for IPv4 and IPv6 alike (#1357). tshark writes an IPv4
 * packet's source in {@code ip.src} and an IPv6 packet's in {@code ipv6.src}, so a pass that asks
 * only for {@code ip.src} silently drops every IPv6 packet.
 *
 * <p>{@link #withIpv6} appends the IPv6 twin of each IPv4 address field to the end of a field list;
 * {@link #fold} puts the twin's value into the IPv4 slot when that slot is empty and drops the
 * twins, so a parser written for the IPv4 layout reads both families unchanged. The twins go last
 * on purpose: a parser can then still read fields counted from either end, even past a value that
 * contains the separator (a DNS name, a URI).
 */
public final class TsharkAddressFields {

  private TsharkAddressFields() {}

  private static final Map<String, String> TWIN =
      Map.of("ip.src", "ipv6.src", "ip.dst", "ipv6.dst");

  /** {@code fields} with {@code ipv6.src} / {@code ipv6.dst} appended for each {@code ip.src} / {@code ip.dst}. */
  public static String[] withIpv6(String... fields) {
    List<String> out = new ArrayList<>(Arrays.asList(fields));
    for (String f : fields) if (TWIN.containsKey(f)) out.add(TWIN.get(f));
    return out.toArray(String[]::new);
  }

  /**
   * A tshark command: {@code fixed} (the program, the file, the filter, the output options), then
   * {@code fields} and their IPv6 twins. Read its rows with {@link #fold}.
   */
  public static List<String> command(String[] fields, String... fixed) {
    List<String> cmd = new ArrayList<>(Arrays.asList(fixed));
    cmd.addAll(args(withIpv6(fields)));
    return cmd;
  }

  /** The tshark arguments for a field list: {@code -e f1 -e f2 …}. */
  public static List<String> args(String... fields) {
    List<String> out = new ArrayList<>(fields.length * 2);
    for (String f : fields) {
      out.add("-e");
      out.add(f);
    }
    return out;
  }

  /**
   * A row tshark wrote for {@code withIpv6(fields)}, as the IPv4 layout {@code fields}: each IPv4
   * address slot filled from its twin when empty, and the twins dropped. A row too short to hold
   * the twins comes back as it is.
   */
  public static String[] fold(String[] row, String... fields) {
    List<Integer> slots = new ArrayList<>();
    for (int i = 0; i < fields.length; i++) if (TWIN.containsKey(fields[i])) slots.add(i);
    int n = slots.size();
    if (n == 0 || row.length < fields.length + n) return row;
    String[] out = Arrays.copyOf(row, row.length - n);
    for (int k = 0; k < n; k++) {
      int slot = slots.get(k);
      String twin = firstAddress(row[row.length - n + k]);
      if ((out[slot] == null || out[slot].isBlank()) && twin != null) out[slot] = twin;
    }
    return out;
  }

  /**
   * The first address in a twin's value. With every occurrence asked for, an ICMPv6 error quoting
   * the packet it answers, or IPv6 in IPv6, gives two ("fe80::1,fd00::53", or joined by whatever
   * aggregator the pass set): the outer header's comes first, and is the packet's own.
   */
  static String firstAddress(String value) {
    if (value == null) return null;
    String v = value.trim();
    int end = 0;
    while (end < v.length() && isAddressChar(v.charAt(end))) end++;
    return end == 0 ? null : v.substring(0, end);
  }

  /** Hex, ':' and '.', and a scope id ({@code %eth0}). An aggregator is none of these. */
  private static boolean isAddressChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || c == ':' || c == '.' || c == '%' || c == '_' || c == '-';
  }
}
