package com.tracepcap.common.net;

import java.util.Locale;
import java.util.Map;

/**
 * What a MAC address says about the device behind it (#918 slice 4), beyond its vendor.
 *
 * <ul>
 *   <li><b>Virtual machine:</b> a hypervisor's prefix. VMs cloned from one image often share a MAC,
 *       so it identifies a device less reliably.
 *   <li><b>Container:</b> Docker's {@code 02:42:…} prefix: a container, not a physical device.
 *   <li><b>Virtual router:</b> a VRRP, CARP or HSRP failover pair's shared MAC (#918). It stands
 *       for a router pair's address, not one machine; VRRP members send their adverts from it too.
 *   <li><b>Private:</b> the locally-administered bit (0x02 of the first byte) is set, so the device
 *       made the address up. Phones do this per network (iOS 14+, Android 10+) and may rotate it,
 *       so it names no vendor and may not stay the same.
 * </ul>
 */
public enum MacKind {
  VIRTUAL_MACHINE,
  CONTAINER,
  VIRTUAL_ROUTER,
  PRIVATE,
  HARDWARE;

  /** Hypervisor prefixes, lower case, to the hypervisor's name. */
  private static final Map<String, String> HYPERVISORS =
      Map.ofEntries(
          Map.entry("00:50:56", "VMware"),
          Map.entry("00:0c:29", "VMware"),
          Map.entry("00:05:69", "VMware"),
          Map.entry("00:1c:14", "VMware"),
          Map.entry("08:00:27", "VirtualBox"),
          Map.entry("0a:00:27", "VirtualBox"),
          Map.entry("00:15:5d", "Hyper-V"),
          Map.entry("52:54:00", "QEMU/KVM"),
          Map.entry("00:16:3e", "Xen"),
          Map.entry("00:1c:42", "Parallels"));

  public static MacKind of(String mac) {
    String m = normalise(mac);
    if (m == null) return HARDWARE;
    if (HYPERVISORS.containsKey(m.substring(0, 8))) return VIRTUAL_MACHINE;
    if (m.startsWith("02:42:")) return CONTAINER;
    // VRRP/CARP 00:00:5e:00:01:xx, HSRPv1 00:00:0c:07:ac:xx, HSRPv2 00:00:0c:9f:fx:xx.
    if (m.startsWith("00:00:5e:00:01:") || m.startsWith("00:00:0c:07:ac:") || m.matches("00:00:0c:9f:f[0-9a-f]:..")) {
      return VIRTUAL_ROUTER;
    }
    return (Integer.parseInt(m.substring(0, 2), 16) & 0x02) != 0 ? PRIVATE : HARDWARE;
  }

  /** The hypervisor a virtual-machine MAC belongs to, else null. */
  public static String hypervisor(String mac) {
    String m = normalise(mac);
    return m == null ? null : HYPERVISORS.get(m.substring(0, 8));
  }

  /** {@code aa:bb:cc:dd:ee:ff} in lower case, or null when {@code mac} isn't one. */
  static String normalise(String mac) {
    if (mac == null) return null;
    String m = mac.trim().toLowerCase(Locale.ROOT).replace('-', ':');
    return m.matches("([0-9a-f]{2}:){5}[0-9a-f]{2}") ? m : null;
  }
}
