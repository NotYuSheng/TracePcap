package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import java.util.Comparator;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

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
  private final PlatformTransactionManager transactions;

  /**
   * In a transaction of its own, in address order. The cache is shared: written inside the analysis
   * transaction, its row locks were held for the minutes the analysis runs, two analyses caching
   * the same addresses in different orders could deadlock, and a failed write aborted the analysis
   * around it (the caller's catch can't undo that). A read-only request can't write at all. A cache
   * entry is worth keeping whatever happens to the caller.
   */
  @Override
  public void upsertAll(Collection<IpGeoInfoEntity> entries) {
    if (entries == null || entries.isEmpty()) return;
    TransactionTemplate tx = new TransactionTemplate(transactions);
    tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    List<IpGeoInfoEntity> ordered = new ArrayList<>(entries);
    ordered.sort(Comparator.comparing(IpGeoInfoEntity::getIp));
    tx.executeWithoutResult(status -> write(ordered));
  }

  private void write(List<IpGeoInfoEntity> entries) {
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
