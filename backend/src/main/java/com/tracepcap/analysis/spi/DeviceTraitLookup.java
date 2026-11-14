package com.tracepcap.analysis.spi;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * What a device shows of itself apart from its MAC (#918 slice 4b), for telling whether two MACs
 * are one device: a phone with a private MAC that changed keeps its DHCP fingerprint, hostname,
 * TLS client fingerprints and signed-in user.
 */
public interface DeviceTraitLookup {

  /**
   * @param key the device's key in the file ({@link DeviceKeys})
   * @param dhcpFingerprints the option lists it asked DHCP for (option 55, comma-joined)
   * @param vendorClasses its DHCP vendor classes (option 60)
   * @param tlsFingerprints JA3 of the TLS connections it opened
   * @param firstSeen its first activity in the file
   * @param lastSeen its last activity in the file
   */
  record DeviceTraits(
      String key,
      String mac,
      String hostname,
      Set<String> dhcpFingerprints,
      Set<String> vendorClasses,
      Set<String> tlsFingerprints,
      String loggedInUser,
      LocalDateTime firstSeen,
      LocalDateTime lastSeen) {}

  /** The device {@code key} names in the file, as of its own stretch on a reused address. */
  Optional<DeviceTraits> traits(UUID fileId, String key, String mac);
}
