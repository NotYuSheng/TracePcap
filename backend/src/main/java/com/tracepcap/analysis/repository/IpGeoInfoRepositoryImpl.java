package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;

/** The {@link IpGeoInfoRepositoryCustom} half of {@link IpGeoInfoRepository}. */
@RequiredArgsConstructor
class IpGeoInfoRepositoryImpl implements IpGeoInfoRepositoryCustom {

  private static final String UPSERT =
      "INSERT INTO ip_geo_cache (ip, country, country_code, asn, org, region, city, lat, lon,"
          + " geo_source, looked_up_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          + " ON CONFLICT (ip) DO UPDATE SET country = EXCLUDED.country,"
          + " country_code = EXCLUDED.country_code, asn = EXCLUDED.asn, org = EXCLUDED.org,"
          + " region = EXCLUDED.region, city = EXCLUDED.city, lat = EXCLUDED.lat, lon = EXCLUDED.lon,"
          + " geo_source = EXCLUDED.geo_source, looked_up_at = EXCLUDED.looked_up_at";

  private static final int BATCH = 1_000;

  private final JdbcTemplate jdbc;

  @Override
  public void upsertAll(Collection<IpGeoInfoEntity> entries) {
    if (entries == null || entries.isEmpty()) return;
    List<Object[]> rows = new ArrayList<>(Math.min(entries.size(), BATCH));
    for (IpGeoInfoEntity e : entries) {
      rows.add(new Object[] {
        e.getIp(), e.getCountry(), e.getCountryCode(), e.getAsn(), e.getOrg(), e.getRegion(),
        e.getCity(), e.getLat(), e.getLon(), e.getGeoSource(),
        e.getLookedUpAt() == null ? null : Timestamp.valueOf(e.getLookedUpAt())
      });
      if (rows.size() == BATCH) {
        jdbc.batchUpdate(UPSERT, rows);
        rows.clear();
      }
    }
    if (!rows.isEmpty()) jdbc.batchUpdate(UPSERT, rows);
  }
}
