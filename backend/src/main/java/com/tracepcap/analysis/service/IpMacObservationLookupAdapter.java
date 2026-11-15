package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.IpMacObservationEntity;
import com.tracepcap.analysis.repository.IpMacObservationRepository;
import com.tracepcap.analysis.spi.IpMacObservationLookup;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Serves {@link IpMacObservationLookup} from the analysis module's own repository. */
@Component
@RequiredArgsConstructor
public class IpMacObservationLookupAdapter implements IpMacObservationLookup {

  private final IpMacObservationRepository repository;

  @Override
  public List<IpMacs> ipMacObservations(UUID fileId) {
    return group(repository.findByFileId(fileId));
  }

  @Override
  public List<IpMacs> ipMacObservationsForIp(UUID fileId, String ip) {
    return group(repository.findByFileIdAndIpOrderById(fileId, ip));
  }

  @Override
  public List<IpMacs> ipMacObservationsForMac(UUID fileId, String mac) {
    return group(repository.findByFileIdForIpsClaimedByMac(fileId, mac));
  }

  private static List<IpMacs> group(List<IpMacObservationEntity> rows) {
    Map<String, List<String>> byIp = new LinkedHashMap<>();
    for (IpMacObservationEntity o : rows) {
      byIp.computeIfAbsent(o.getIp(), k -> new ArrayList<>()).add(o.getMac());
    }
    return byIp.entrySet().stream()
        .map(e -> new IpMacs(e.getKey(), List.copyOf(e.getValue())))
        .toList();
  }
}
