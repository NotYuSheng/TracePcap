package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import com.tracepcap.analysis.spi.GeoOrgLookup;
import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Serves {@link GeoOrgLookup} from the analysis module's own geo cache. */
@Component
@RequiredArgsConstructor
public class GeoOrgLookupAdapter implements GeoOrgLookup {

  private final IpGeoInfoRepository repository;

  @Override
  public List<String> orgsFor(Collection<String> ips) {
    if (ips == null || ips.isEmpty()) return List.of();
    return repository.findAllByIpIn(ips).stream()
        .map(IpGeoInfoEntity::getOrg)
        .filter(o -> o != null && !o.isBlank())
        .distinct()
        .toList();
  }
}
