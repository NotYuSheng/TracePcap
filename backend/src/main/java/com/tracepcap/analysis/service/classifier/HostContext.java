package com.tracepcap.analysis.service.classifier;

import java.util.Set;

/**
 * Immutable bundle of everything a {@link DeviceClassificationSignal} may inspect about one host:
 * its identity (IP/MAC/vendor/hostname), its observed TTL, its traffic {@link HostProfile}, and the
 * set of service roles it was detected playing (e.g. {@code "dns"}).
 *
 * @param ip the host's IP address
 * @param profile accumulated traffic profile
 * @param ttl first-seen IP TTL (may be null)
 * @param mac first-seen MAC (may be null)
 * @param manufacturer OUI vendor name (may be null)
 * @param ouiHint device-type hint derived from the vendor (may be null)
 * @param hostname passively-discovered hostname (may be null)
 * @param serviceRoles roles this host was detected serving (never null; possibly empty)
 */
public record HostContext(
    String ip,
    HostProfile profile,
    Integer ttl,
    String mac,
    String manufacturer,
    String ouiHint,
    String hostname,
    Set<String> serviceRoles) {

  /** True when this host was detected serving the given role (e.g. {@code "dns"}). */
  public boolean hasServiceRole(String role) {
    return serviceRoles != null && serviceRoles.contains(role);
  }
}
