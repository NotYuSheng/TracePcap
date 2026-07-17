package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import com.tracepcap.analysis.spi.GeoOrgLookup;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

  @Override
  public Map<String, IpAttribution> attributionFor(Collection<String> ips) {
    if (ips == null || ips.isEmpty()) return Map.of();
    Map<String, IpAttribution> byIp = new LinkedHashMap<>();
    for (IpGeoInfoEntity g : repository.findAllByIpIn(ips)) {
      // First record wins on a duplicate IP — the cache is keyed by IP, so this is belt-and-braces,
      // but putIfAbsent keeps the choice deterministic rather than last-write-wins.
      byIp.putIfAbsent(
          g.getIp(), new IpAttribution(g.getIp(), g.getAsn(), g.getOrg(), g.getCountryCode()));
    }
    return Map.copyOf(byIp);
  }
}
