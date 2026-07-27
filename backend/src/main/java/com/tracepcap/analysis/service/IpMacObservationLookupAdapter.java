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
    Map<String, List<String>> byIp = new LinkedHashMap<>();
    for (IpMacObservationEntity o : repository.findByFileId(fileId)) {
      byIp.computeIfAbsent(o.getIp(), k -> new ArrayList<>()).add(o.getMac());
    }
    return byIp.entrySet().stream()
        .map(e -> new IpMacs(e.getKey(), List.copyOf(e.getValue())))
        .toList();
  }
}
