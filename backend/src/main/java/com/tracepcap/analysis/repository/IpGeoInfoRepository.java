package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface IpGeoInfoRepository extends JpaRepository<IpGeoInfoEntity, String> {

  List<IpGeoInfoEntity> findAllByIpIn(Collection<String> ips);

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
   * Inserts or refreshes one cache entry in a single statement. Two analyses running at once can
   * look up the same external IP; a plain insert from the second then violated the primary key and,
   * being inside the analysis transaction, aborted that whole analysis.
   */
  @org.springframework.data.jpa.repository.Modifying
  @org.springframework.transaction.annotation.Transactional
  @Query(
      value =
          "INSERT INTO ip_geo_cache (ip, country, country_code, asn, org, region, city, lat, lon, geo_source, looked_up_at)"
              + " VALUES (:#{#e.ip}, :#{#e.country}, :#{#e.countryCode}, :#{#e.asn}, :#{#e.org}, :#{#e.region},"
              + " :#{#e.city}, :#{#e.lat}, :#{#e.lon}, :#{#e.geoSource}, :#{#e.lookedUpAt})"
              + " ON CONFLICT (ip) DO UPDATE SET country = EXCLUDED.country, country_code = EXCLUDED.country_code,"
              + " asn = EXCLUDED.asn, org = EXCLUDED.org, region = EXCLUDED.region, city = EXCLUDED.city,"
              + " lat = EXCLUDED.lat, lon = EXCLUDED.lon, geo_source = EXCLUDED.geo_source,"
              + " looked_up_at = EXCLUDED.looked_up_at",
      nativeQuery = true)
  void upsert(@Param("e") IpGeoInfoEntity e);
}
