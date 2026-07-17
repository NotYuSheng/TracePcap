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
                    e.getRunnerUpScore()))
        .toList();
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
        e.getTtl(),
        e.getDeviceType(),
        e.getConfidence(),
        splitRoles(e.getServiceRoles()));
  }

  /** Splits the comma-joined service_roles column into a list (empty when null/blank). */
  private static List<String> splitRoles(String joined) {
    if (joined == null || joined.isBlank()) return List.of();
    return Arrays.stream(joined.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
  }
}
