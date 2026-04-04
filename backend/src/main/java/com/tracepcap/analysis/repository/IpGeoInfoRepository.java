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
}
