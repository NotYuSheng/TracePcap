package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Checks on what a "host" is (#918 items 1c and 2), applied after classification.
 *
 * <ul>
 *   <li><b>Every TTL</b> seen from the IP is kept, not just the first.
 *   <li><b>Virtual addresses.</b> A VRRP/HSRP/CARP virtual IP, from the adverts or an ARP claim by a
 *       virtual-router MAC, is marked VIRTUAL_FAILOVER and its device type set to VIRTUAL_ADDRESS, with the member
 *       routers in the explanation. The protocol says so, so it replaces the traffic vote (which
 *       used to call these "IoT", from the IANA MAC's manufacturer).
 *   <li><b>Possibly more than one machine.</b> Different TTL families on one IP (64 Linux/macOS, 128
 *       Windows, 255 network gear), or several DHCP hostnames, add an identity warning. Cloned VMs,
 *       a duplicated MAC, NAT, or DHCP handing the IP to another device can all cause it; the
 *       warning says what was seen, not which.
 * </ul>
 */
final class HostIdentityChecks {

  static final String VIRTUAL_FAILOVER = "VIRTUAL_FAILOVER";
  static final String VIRTUAL_ADDRESS_TYPE = "VIRTUAL_ADDRESS";

  private HostIdentityChecks() {}

  static void apply(
      List<HostClassificationEntity> hosts,
      Map<String, ? extends Collection<Integer>> ttlObservations,
      List<HostnameResolverService.Claim> hostnameClaims,
      Map<String, FailoverAddressResolverService.VirtualAddress> failover,
      Map<String, ? extends Collection<String>> arpMacs,
      Set<String> reusedAddresses) {
    // The routers sending adverts are members, not virtual addresses, even though VRRP sends its
    // adverts from the virtual MAC.
    Set<String> members = new java.util.HashSet<>();
    if (failover != null) failover.values().forEach(v -> { if (v.members() != null) members.addAll(v.members()); });
    Map<String, Set<String>> dhcpNames = new java.util.HashMap<>();
    if (hostnameClaims != null) {
      for (var c : hostnameClaims) {
        if (HostnameResolverService.SOURCE_DHCP.equals(c.source()) && c.hostname() != null) {
          dhcpNames.computeIfAbsent(c.ip(), k -> new TreeSet<>(String.CASE_INSENSITIVE_ORDER)).add(c.hostname());
        }
      }
    }
    for (HostClassificationEntity h : hosts) {
      Collection<Integer> ttls = ttlObservations == null ? null : ttlObservations.get(h.getIp());
      if (ttls != null && !ttls.isEmpty()) h.setTtls(new TreeSet<>(ttls).toArray(Integer[]::new));

      var advertised = failover == null ? null : failover.get(h.getIp());
      // Only ARP ownership counts for the MAC check: who answers for the address.
      String macProtocol = null;
      if (!members.contains(h.getIp()) && arpMacs != null && arpMacs.get(h.getIp()) != null) {
        for (String mac : arpMacs.get(h.getIp())) {
          macProtocol = FailoverAddressResolverService.virtualRouterProtocol(mac);
          if (macProtocol != null) break;
        }
      }
      if (advertised != null || macProtocol != null) {
        markVirtual(h, advertised != null ? advertised.protocol() : macProtocol, advertised);
        continue; // a shared address: the per-machine checks below don't apply
      }

      List<String> warnings = new ArrayList<>();
      Set<Integer> families = new TreeSet<>();
      if (ttls != null) ttls.forEach(t -> families.add(family(t)));
      if (families.size() > 1) {
        warnings.add("TTLs from different operating-system families (" + describeFamilies(families) + ")");
      }
      Set<String> names = dhcpNames.get(h.getIp());
      if (names != null && names.size() > 1) {
        warnings.add("several DHCP hostnames (" + String.join(", ", names) + ")");
      }
      // An address that passed between devices (#918 item 3) shows its occupancy timeline instead:
      // the differing TTLs and names belong to different devices, which the timeline already says.
      boolean reused = reusedAddresses != null && reusedAddresses.contains(h.getIp());
      if (!warnings.isEmpty() && !reused) {
        h.setIdentityWarning(
            "Possibly more than one machine: "
                + String.join("; ", warnings)
                + ". Cloned VMs, a duplicated MAC, NAT, or the address passing to another device can"
                + " all cause this.");
      }
    }
  }

  private static void markVirtual(
      HostClassificationEntity h, String protocol, FailoverAddressResolverService.VirtualAddress advertised) {
    h.setAddressKind(VIRTUAL_FAILOVER);
    h.setDeviceType(VIRTUAL_ADDRESS_TYPE);
    h.setConfidence(100);
    StringBuilder why = new StringBuilder("Virtual address of a " + protocol + " router failover pair");
    if (advertised != null && advertised.members() != null && !advertised.members().isEmpty()) {
      why.append(", shared by ").append(String.join(", ", advertised.members()));
    } else {
      why.append(" (answered by a virtual-router MAC)");
    }
    why.append(". It's an address, not a machine.");
    h.setWinnerReasons(why.toString());
    h.setWinnerScore(null);
    h.setRunnerUpType(null);
    h.setRunnerUpScore(null);
    h.setRunnerUpReasons(null);
  }

  /** The initial TTL a value most likely started from: 64, 128 or 255. */
  static int family(int ttl) {
    if (ttl <= 64) return 64;
    if (ttl <= 128) return 128;
    return 255;
  }

  private static String describeFamilies(Set<Integer> families) {
    List<String> out = new ArrayList<>();
    for (int f : families) {
      out.add(
          switch (f) {
            case 64 -> "≤64, e.g. Linux or macOS";
            case 128 -> "≤128, e.g. Windows";
            default -> "≤255, e.g. network equipment";
          });
    }
    return String.join(" and ", out);
  }
}
