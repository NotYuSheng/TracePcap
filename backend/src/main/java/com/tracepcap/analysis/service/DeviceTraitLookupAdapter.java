package com.tracepcap.analysis.service;

import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.DhcpLeaseRepository;
import com.tracepcap.analysis.spi.DeviceKeys;
import com.tracepcap.analysis.spi.DeviceTraitLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Serves {@link DeviceTraitLookup} from the analysis module's tables. */
@Component
@RequiredArgsConstructor
public class DeviceTraitLookupAdapter implements DeviceTraitLookup {

  private final DhcpLeaseRepository leases;
  private final ConversationRepository conversations;
  private final HostClassificationLookup hosts;

  @Override
  @Transactional(readOnly = true)
  public Optional<DeviceTraits> traits(UUID fileId, String key, String mac) {
    String ip = DeviceKeys.ipOf(key);
    var span = hosts.deviceSpan(fileId, key);
    LocalDateTime from = span.map(HostClassificationLookup.DeviceSpan::startsAt).orElse(null);
    LocalDateTime to = span.map(HostClassificationLookup.DeviceSpan::endsAt).orElse(null);
    var facts = span.isPresent() ? hosts.deviceFacts(fileId, key) : hosts.hostFactsByIp(fileId, ip);

    Set<String> dhcp = new TreeSet<>();
    Set<String> vendors = new TreeSet<>();
    for (var l : leases.findByFileIdAndIp(fileId, ip)) {
      if (mac != null && !mac.equalsIgnoreCase(l.getMac())) continue;
      if (l.getFingerprint() != null) dhcp.add(l.getFingerprint());
      if (l.getVendorClass() != null) vendors.add(l.getVendorClass());
    }
    Set<String> tls = new TreeSet<>();
    for (Object[] row : conversations.findClientJa3ByFileIdAndIp(fileId, ip)) {
      if (within((LocalDateTime) row[0], from, to)) tls.add((String) row[1]);
    }
    LocalDateTime first = null;
    LocalDateTime last = null;
    for (Object[] row : conversations.findTimesByFileIdAndIp(fileId, ip)) {
      LocalDateTime s = (LocalDateTime) row[0];
      LocalDateTime e = row[1] != null ? (LocalDateTime) row[1] : s;
      if (s == null || !within(s, from, to)) continue;
      if (first == null || s.isBefore(first)) first = s;
      if (last == null || e.isAfter(last)) last = e;
    }
    return Optional.of(
        new DeviceTraits(
            key,
            mac,
            facts.map(HostClassificationLookup.HostFacts::hostname).orElse(null),
            dhcp,
            vendors,
            tls,
            facts.map(HostClassificationLookup.HostFacts::loggedInUser).orElse(null),
            first,
            last));
  }

  private static boolean within(LocalDateTime t, LocalDateTime from, LocalDateTime to) {
    if (t == null) return from == null;
    return (from == null || !t.isBefore(from)) && (to == null || t.isBefore(to));
  }
}
