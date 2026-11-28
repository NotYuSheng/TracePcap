package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface IpGeoInfoRepository
    extends JpaRepository<IpGeoInfoEntity, String>, IpGeoInfoRepositoryCustom {

  /** Use {@link #findByIps}: this binds one parameter per address, unbounded. */
  List<IpGeoInfoEntity> findAllByIpIn(Collection<String> ips);

  /**
   * The cached entries for these addresses, looked up a batch at a time. One IN with every address
   * of a scan capture (200k) ran the analysis out of heap building the query, and Postgres takes
   * at most 65,535 bind parameters anyway.
   */
  default List<IpGeoInfoEntity> findByIps(Collection<String> ips) {
    return com.tracepcap.common.db.InBatches.of(ips, this::findAllByIpIn);
  }

  /**
   * Returns distinct (countryCode, country) pairs for any external IP that appears as srcIp or
   * dstIp in conversations belonging to the given file.
   */
  @Query(
      value =
          "SELECT g.country_code, MIN(g.country) AS country"
              + " FROM ip_geo_cache g"
              + " WHERE g.ip IN ("
              + "   SELECT src_ip FROM conversations WHERE file_id = :fileId"
              + "   UNION ALL"
              + "   SELECT dst_ip FROM conversations WHERE file_id = :fileId"
              + " )"
              + " AND g.country_code IS NOT NULL"
              + " GROUP BY g.country_code"
              + " ORDER BY MIN(g.country)",
      nativeQuery = true)
  List<Object[]> findDistinctCountriesByFileId(@Param("fileId") java.util.UUID fileId);

  /**
   * Which of these addresses are cached and need no refresh: looked up within the TTL, and not a
   * country-only entry missing its coordinates. The rules {@code GeoIpService.lookupExternal} uses.
   */
  @Query(
      "SELECT g.ip FROM IpGeoInfoEntity g WHERE g.ip IN :ips"
          + " AND NOT (g.lat IS NULL AND g.countryCode IS NOT NULL)"
          + " AND (g.lookedUpAt IS NULL OR g.lookedUpAt >= :since)")
  List<String> findFreshIps(
      @Param("ips") Collection<String> ips, @Param("since") java.time.LocalDateTime since);

  /** One entry: {@link #upsertAll}. */
  default void upsert(IpGeoInfoEntity e) {
    upsertAll(java.util.List.of(e));
  }
}
