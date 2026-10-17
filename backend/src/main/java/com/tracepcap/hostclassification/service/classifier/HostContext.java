package com.tracepcap.hostclassification.service.classifier;

import com.tracepcap.analysis.service.WindowsIdentityResolverService;
import java.util.List;
import java.util.Set;

/**
 * Immutable bundle of everything a {@link DeviceClassificationSignal} may inspect about one host:
 * its identity (IP/MAC/vendor/hostname), its observed TTL, its traffic {@link HostProfile}, the set
 * of service roles it was detected playing (e.g. {@code "dns"}), and any Windows sign-in claims
 * (Kerberos/LDAP) observed from it.
 *
 * @param ip the host's IP address
 * @param profile accumulated traffic profile
 * @param ttl first-seen IP TTL (may be null)
 * @param mac first-seen MAC (may be null)
 * @param manufacturer OUI vendor name (may be null)
 * @param ouiHint device-type hint derived from the vendor (may be null)
 * @param hostname passively-discovered hostname (may be null)
 * @param serviceRoles roles this host was detected serving (never null; possibly empty)
 * @param windowsIdentityClaims Windows sign-in claims observed from this host (never null; possibly
 *     empty) — Kerberos AS-REQ / LDAP-DN evidence that it is a domain-joined Windows workstation
 */
public record HostContext(
    String ip,
    HostProfile profile,
    Integer ttl,
    String mac,
    String manufacturer,
    String ouiHint,
    String hostname,
    Set<String> serviceRoles,
    List<WindowsIdentityResolverService.Claim> windowsIdentityClaims) {

  /** Enforces the documented non-null contract and makes the collections immutable. */
  public HostContext {
    serviceRoles = (serviceRoles == null) ? Set.of() : Set.copyOf(serviceRoles);
    windowsIdentityClaims =
        (windowsIdentityClaims == null) ? List.of() : List.copyOf(windowsIdentityClaims);
  }

  /** Convenience for signals (and their tests) that don't involve Windows sign-in claims. */
  public HostContext(
      String ip,
      HostProfile profile,
      Integer ttl,
      String mac,
      String manufacturer,
      String ouiHint,
      String hostname,
      Set<String> serviceRoles) {
    this(ip, profile, ttl, mac, manufacturer, ouiHint, hostname, serviceRoles, List.of());
  }

  /** True when this host was detected serving the given role (e.g. {@code "dns"}). */
  public boolean hasServiceRole(String role) {
    return serviceRoles.contains(role);
  }
}
