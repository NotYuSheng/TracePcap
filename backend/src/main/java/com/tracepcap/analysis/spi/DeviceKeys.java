package com.tracepcap.analysis.spi;

import java.time.LocalDateTime;

/**
 * Keys for one device on an address that more than one device held (#918 slice 3). Labels, roles
 * and analyst evidence attach to a key, so they can be put on one device rather than the address.
 *
 * <ul>
 *   <li>The first device keeps the bare IP, so a label made before the address was split stays on
 *       the device that held it first, and an address one device held is keyed as it always was.
 *   <li>A later device is {@code ip@<start>}, its start time as {@link LocalDateTime#toString}. A
 *       start time, not a position: a manual split renumbers every later device, and labels keyed by
 *       position would move to the wrong one.
 *   <li>A device on another network that uses the same range (#462) is {@code ip~<network>}, the
 *       network's key (e.g. {@code vlan:20}), with {@code @<start>} after it if it also changed hands.
 * </ul>
 */
public final class DeviceKeys {

  private DeviceKeys() {}

  /** The key for the device holding {@code ip} from {@code startsAt}; null start = the first device. */
  public static String key(String ip, LocalDateTime startsAt) {
    return startsAt == null ? ip : ip + "@" + startsAt;
  }

  /** The key for a device on another network ({@code network}), from {@code startsAt} (null = all along). */
  public static String key(String ip, String network, LocalDateTime startsAt) {
    String base = network == null ? ip : ip + "~" + network;
    return startsAt == null ? base : base + "@" + startsAt;
  }

  /** Whether {@code key} names a device ({@code ip@<start>} or {@code ip~<network>}) rather than an address. */
  public static boolean isDeviceKey(String key) {
    return key != null && end(key) < key.length();
  }

  /** The address part of a key. */
  public static String ipOf(String key) {
    return key == null ? null : key.substring(0, end(key));
  }

  /** The network part of a key ({@code ip~<network>}); null when it has none. */
  public static String networkOf(String key) {
    if (key == null) return null;
    int t = key.indexOf('~');
    if (t <= 0) return null;
    int at = key.indexOf('@', t);
    return at < 0 ? key.substring(t + 1) : key.substring(t + 1, at);
  }

  /** The start time of a later device's key; null for a bare IP or a malformed key. */
  public static LocalDateTime startOf(String key) {
    if (key == null) return null;
    // An IPv6 address has no '@' or '~', and a network key has no '@', so the last '@' is the start's.
    int at = key.lastIndexOf('@');
    if (at <= 0) return null;
    try {
      return LocalDateTime.parse(key.substring(at + 1));
    } catch (RuntimeException e) {
      return null;
    }
  }

  /** Where the address part of a key ends: at its first '~' or '@'. */
  private static int end(String key) {
    int t = key.indexOf('~');
    int at = key.indexOf('@');
    int e = key.length();
    if (t > 0) e = Math.min(e, t);
    if (at > 0) e = Math.min(e, at);
    return e;
  }
}
