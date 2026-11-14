package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Serves {@link HostClassificationLookup} from the analysis module's own repository. */
@Component
@RequiredArgsConstructor
public class HostClassificationLookupAdapter implements HostClassificationLookup {

  private final HostClassificationRepository repository;
  private final com.tracepcap.analysis.repository.IpOccupancyRepository occupancies;

  @Override
  public List<ClassifiedHost> classifiedHosts(UUID fileId) {
    return repository.findByFileId(fileId).stream()
        .map(
            e ->
                new ClassifiedHost(
                    e.getIp(),
                    e.getDeviceType(),
                    e.getConfidence(),
                    e.getWinnerScore(),
                    e.getRunnerUpType(),
                    e.getRunnerUpScore(),
                    splitReasons(e.getWinnerReasons()),
                    splitReasons(e.getRunnerUpReasons())))
        .toList();
  }

  @Override
  public List<ClassifiedHost> deviceHosts(UUID fileId) {
    List<ClassifiedHost> out = new java.util.ArrayList<>();
    for (var o : occupancies.findByFileIdOrderByIpAscIdxAsc(fileId)) {
      if (o.getDeviceType() == null) continue; // not classified (no traffic in its stretch)
      out.add(
          new ClassifiedHost(
              com.tracepcap.analysis.spi.DeviceKeys.key(o.getIp(), o.getStartsAt()),
              o.getDeviceType(),
              o.getConfidence() == null ? 0 : o.getConfidence(),
              o.getWinnerScore(),
              o.getRunnerUpType(),
              o.getRunnerUpScore(),
              splitReasons(o.getWinnerReasons()),
              splitReasons(o.getRunnerUpReasons())));
    }
    return out;
  }

  @Override
  public Optional<DeviceSpan> deviceSpan(UUID fileId, String key) {
    return occupancyFor(fileId, key).map(found -> new DeviceSpan(
        found.row().getIp(), key, found.row().getIdx(), found.of(), found.row().getStartsAt(), found.row().getEndsAt()));
  }

  @Override
  public Optional<HostFacts> deviceFacts(UUID fileId, String key) {
    var found = occupancyFor(fileId, key);
    if (found.isEmpty()) return Optional.empty();
    var o = found.get().row();
    HostFacts a = hostFactsByIp(fileId, o.getIp()).orElse(null);
    return Optional.of(
        new HostFacts(
            key,
            o.getMac(),
            o.getManufacturer(),
            o.getHostname(),
            o.getHostname() == null ? null : "dhcp",
            o.getLoggedInUser(),
            null,
            null,
            o.getLoggedInUser() == null ? 0 : 1,
            o.getTtl(),
            o.getDeviceType() == null ? (a == null ? "UNKNOWN" : a.deviceType()) : o.getDeviceType(),
            o.getConfidence() == null ? 0 : o.getConfidence(),
            a == null ? List.of() : a.serviceRoles(),
            o.getTtl() == null ? List.of() : List.of(o.getTtl()),
            a == null ? null : a.addressKind(),
            null,
            null));
  }

  @Override
  public List<HostFacts> deviceInventory(UUID fileId) {
    List<HostFacts> hosts = hostFacts(fileId);
    var rows = occupancies.findByFileIdOrderByIpAscIdxAsc(fileId);
    if (rows.isEmpty()) return hosts;
    java.util.Set<String> reused = new java.util.HashSet<>();
    for (var o : rows) reused.add(o.getIp());
    List<HostFacts> out = new java.util.ArrayList<>();
    for (HostFacts h : hosts) if (!reused.contains(h.ip())) out.add(h);
    for (var o : rows) {
      deviceFacts(fileId, com.tracepcap.analysis.spi.DeviceKeys.key(o.getIp(), o.getStartsAt())).ifPresent(out::add);
    }
    return out;
  }

  @Override
  public Optional<String> keyForMac(UUID fileId, String mac) {
    if (mac == null) return Optional.empty();
    for (var o : occupancies.findByFileIdAndMacIgnoreCaseOrderByIpAscIdxAsc(fileId, mac)) {
      return Optional.of(com.tracepcap.analysis.spi.DeviceKeys.key(o.getIp(), o.getStartsAt()));
    }
    return hostFactsByMac(fileId, mac).map(HostFacts::ip);
  }

  private record Found(com.tracepcap.analysis.entity.IpOccupancyEntity row, int of) {}

  /** The occupancy {@code key} names, when its address has more than one. */
  private Optional<Found> occupancyFor(UUID fileId, String key) {
    String ip = com.tracepcap.analysis.spi.DeviceKeys.ipOf(key);
    var rows = occupancies.findByFileIdAndIpOrderByIdx(fileId, ip);
    if (rows.size() < 2) return Optional.empty();
    for (var o : rows) {
      if (com.tracepcap.analysis.spi.DeviceKeys.key(ip, o.getStartsAt()).equals(key)) return Optional.of(new Found(o, rows.size()));
    }
    return Optional.empty();
  }

  @Override
  public List<HostFacts> hostFacts(UUID fileId) {
    return repository.findByFileId(fileId).stream().map(HostClassificationLookupAdapter::toFacts).toList();
  }

  @Override
  public Optional<HostFacts> hostFactsByIp(UUID fileId, String ip) {
    return repository
        .findFirstByFileIdAndIpOrderByIdAsc(fileId, ip)
        .map(HostClassificationLookupAdapter::toFacts);
  }

  @Override
  public Optional<HostFacts> hostFactsByMac(UUID fileId, String mac) {
    return repository
        .findFirstByFileIdAndMacIgnoreCaseOrderByIdAsc(fileId, mac)
        .map(HostClassificationLookupAdapter::toFacts);
  }

  @Override
  public long hostCount(UUID fileId) {
    return repository.countByFileId(fileId);
  }

  private static HostFacts toFacts(HostClassificationEntity e) {
    return new HostFacts(
        e.getIp(),
        e.getMac(),
        e.getManufacturer(),
        e.getHostname(),
        e.getHostnameSource(),
        e.getLoggedInUser(),
        e.getLoggedInUserSource(),
        e.getLoggedInUserRealName(),
        e.getLoggedInUserCount(),
        e.getTtl(),
        e.getDeviceType(),
        e.getConfidence(),
        splitRoles(e.getServiceRoles()),
        e.getTtls() == null ? List.of() : List.of(e.getTtls()),
        e.getAddressKind(),
        e.getIdentityWarning(),
        e.getRescoredAt() == null
            ? null
            : new HostClassificationLookup.Reclassified(
                e.getRescoredAt(), e.getRescoredFrom(), e.getRescoredBy(), e.getRescoredRules()));
  }

  /** Splits the comma-joined service_roles column into a list (empty when null/blank). */
  private static List<String> splitRoles(String joined) {
    if (joined == null || joined.isBlank()) return List.of();
    return Arrays.stream(joined.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
  }

  /**
   * Splits the newline-joined reasons column into a list (empty when null/blank). Newline, not
   * comma: a reason may itself contain a comma, so it must not be the delimiter.
   */
  private static List<String> splitReasons(String joined) {
    if (joined == null || joined.isBlank()) return List.of();
    return Arrays.stream(joined.split("\n")).map(String::trim).filter(s -> !s.isEmpty()).toList();
  }
}
