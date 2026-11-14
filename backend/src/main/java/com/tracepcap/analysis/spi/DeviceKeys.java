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
 * </ul>
 */
public final class DeviceKeys {

  private DeviceKeys() {}

  /** The key for the device holding {@code ip} from {@code startsAt}; null start = the first device. */
  public static String key(String ip, LocalDateTime startsAt) {
    return startsAt == null ? ip : ip + "@" + startsAt;
  }

  /** Whether {@code key} names a later device ({@code ip@<start>}) rather than an address. */
  public static boolean isDeviceKey(String key) {
    return key != null && key.indexOf('@') > 0;
  }

  /** The address part of a key. */
  public static String ipOf(String key) {
    if (key == null) return null;
    int at = key.indexOf('@');
    return at > 0 ? key.substring(0, at) : key;
  }

  /** The start time of a later device's key; null for a bare IP or a malformed key. */
  public static LocalDateTime startOf(String key) {
    if (!isDeviceKey(key)) return null;
    try {
      return LocalDateTime.parse(key.substring(key.indexOf('@') + 1));
    } catch (RuntimeException e) {
      return null;
    }
  }
}
