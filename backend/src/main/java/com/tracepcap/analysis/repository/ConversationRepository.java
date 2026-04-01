package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import com.tracepcap.analysis.entity.PacketEntity;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Subquery;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ConversationRepository
    extends JpaRepository<ConversationEntity, UUID>, JpaSpecificationExecutor<ConversationEntity> {

  List<ConversationEntity> findByFileId(UUID fileId);

  long countByFileId(UUID fileId);

  /** Returns the distinct detected file types present in packets for the given file. */
  @Query(
      "SELECT DISTINCT p.detectedFileType FROM PacketEntity p"
          + " WHERE p.file.id = :fileId AND p.detectedFileType IS NOT NULL"
          + " ORDER BY p.detectedFileType")
  List<String> findDistinctFileTypesByFileId(@Param("fileId") UUID fileId);

  /** Returns only conversations that have at least one risk flag. */
  @Query(
      value =
          "SELECT * FROM conversations WHERE file_id = :fileId"
              + " AND flow_risks IS NOT NULL AND array_length(flow_risks, 1) > 0",
      nativeQuery = true)
  List<ConversationEntity> findByFileIdWithRisks(@Param("fileId") UUID fileId);

  /** Returns the top-N conversations for a file, ordered by total bytes descending. */
  @Query("SELECT c FROM ConversationEntity c WHERE c.file.id = :fileId ORDER BY c.totalBytes DESC")
  List<ConversationEntity> findTopByFileIdOrderByTotalBytesDesc(
      @Param("fileId") UUID fileId, Pageable pageable);

  /**
   * Returns at-risk conversations for a file, capped to a limit. Uses native query because JPQL
   * cannot express array_length.
   */
  @Query(
      value =
          "SELECT * FROM conversations WHERE file_id = :fileId"
              + " AND flow_risks IS NOT NULL AND array_length(flow_risks, 1) > 0"
              + " LIMIT :lim",
      nativeQuery = true)
  List<ConversationEntity> findAtRiskByFileIdLimited(
      @Param("fileId") UUID fileId, @Param("lim") int lim);

  /** Total count of at-risk conversations for a file (used for prompt summary line). */
  @Query(
      value =
          "SELECT COUNT(*) FROM conversations WHERE file_id = :fileId"
              + " AND flow_risks IS NOT NULL AND array_length(flow_risks, 1) > 0",
      nativeQuery = true)
  long countAtRiskByFileId(@Param("fileId") UUID fileId);

  /** Aggregated category → total packet count for a file (avoids loading full entities). */
  @Query(
      "SELECT c.category, SUM(c.packetCount) FROM ConversationEntity c"
          + " WHERE c.file.id = :fileId AND c.category IS NOT NULL AND c.category <> ''"
          + " GROUP BY c.category ORDER BY SUM(c.packetCount) DESC")
  List<Object[]> findCategoryDistributionByFileId(@Param("fileId") UUID fileId);

  /** Returns the distinct risk type strings present across all at-risk conversations for a file. */
  @Query(
      value =
          "SELECT DISTINCT unnest(flow_risks) AS risk_type"
              + " FROM conversations WHERE file_id = :fileId"
              + " AND flow_risks IS NOT NULL AND array_length(flow_risks, 1) > 0"
              + " ORDER BY risk_type",
      nativeQuery = true)
  List<String> findDistinctRiskTypesByFileId(@Param("fileId") UUID fileId);

  /** Returns the distinct custom signature rule names triggered for a file. */
  @Query(
      value =
          "SELECT DISTINCT unnest(custom_signatures) AS rule_name"
              + " FROM conversations WHERE file_id = :fileId"
              + " AND custom_signatures IS NOT NULL AND array_length(custom_signatures, 1) > 0"
              + " ORDER BY rule_name",
      nativeQuery = true)
  List<String> findDistinctCustomSignaturesByFileId(@Param("fileId") UUID fileId);

  /** Build a JPA Specification from the given filter params plus a mandatory fileId constraint. */
  static Specification<ConversationEntity> buildSpec(UUID fileId, ConversationFilterParams params) {

    return (root, query, cb) -> {
      List<Predicate> predicates = new ArrayList<>();

      // Always restrict to the requested file
      predicates.add(cb.equal(root.get("file").get("id"), fileId));

      if (params == null) {
        return cb.and(predicates.toArray(new Predicate[0]));
      }

      // IP / hostname free-text
      if (params.getIp() != null && !params.getIp().isBlank()) {
        String pattern = "%" + params.getIp().trim().toLowerCase() + "%";
        predicates.add(
            cb.or(
                cb.like(cb.lower(root.get("srcIp")), pattern),
                cb.like(cb.lower(root.get("dstIp")), pattern),
                cb.like(cb.lower(cb.coalesce(root.get("hostname"), "")), pattern)));
      }

      // Port exact match (srcPort OR dstPort)
      if (params.getPort() != null) {
        predicates.add(
            cb.or(
                cb.equal(root.get("srcPort"), params.getPort()),
                cb.equal(root.get("dstPort"), params.getPort())));
      }

      // Protocol multi-value
      if (params.getProtocols() != null && !params.getProtocols().isEmpty()) {
        predicates.add(root.get("protocol").in(params.getProtocols()));
      }

      // L7 Protocol multi-value
      if (params.getL7Protocols() != null && !params.getL7Protocols().isEmpty()) {
        predicates.add(root.get("tsharkProtocol").in(params.getL7Protocols()));
      }

      // Application multi-value
      if (params.getApps() != null && !params.getApps().isEmpty()) {
        predicates.add(root.get("appName").in(params.getApps()));
      }

      // Category multi-value
      if (params.getCategories() != null && !params.getCategories().isEmpty()) {
        predicates.add(root.get("category").in(params.getCategories()));
      }

      // Has flow risks or custom signature matches
      if (Boolean.TRUE.equals(params.getHasRisks())) {
        predicates.add(
            cb.or(cb.isNotNull(root.get("flowRisks")), cb.isNotNull(root.get("customSignatures"))));
      }

      // Risk type filter (nDPI flow risks)
      if (params.getRiskTypes() != null && !params.getRiskTypes().isEmpty()) {
        List<Predicate> riskPreds =
            params.getRiskTypes().stream()
                .map(
                    rt ->
                        cb.greaterThan(
                            cb.function(
                                "array_position",
                                Integer.class,
                                root.get("flowRisks"),
                                cb.literal(rt)),
                            0))
                .collect(java.util.stream.Collectors.toList());
        predicates.add(cb.or(riskPreds.toArray(new Predicate[0])));
      }

      // Custom signature filter
      if (params.getCustomSignatures() != null && !params.getCustomSignatures().isEmpty()) {
        List<Predicate> sigPreds =
            params.getCustomSignatures().stream()
                .map(
                    sig ->
                        cb.greaterThan(
                            cb.function(
                                "array_position",
                                Integer.class,
                                root.get("customSignatures"),
                                cb.literal(sig)),
                            0))
                .collect(java.util.stream.Collectors.toList());
        predicates.add(cb.or(sigPreds.toArray(new Predicate[0])));
      }

      // File type multi-value — EXISTS subquery against packets table
      if (params.getFileTypes() != null && !params.getFileTypes().isEmpty()) {
        Subquery<UUID> sub = query.subquery(UUID.class);
        var packet = sub.from(PacketEntity.class);
        sub.select(packet.get("conversation").get("id"))
            .where(
                cb.and(
                    cb.equal(packet.get("conversation").get("id"), root.get("id")),
                    packet.get("detectedFileType").in(params.getFileTypes())));
        predicates.add(cb.exists(sub));
      }

      // Device type filter — srcIp or dstIp is classified with one of the given device types
      if (params.getDeviceTypes() != null && !params.getDeviceTypes().isEmpty()) {
        Subquery<String> deviceTypeSub = query.subquery(String.class);
        var host = deviceTypeSub.from(HostClassificationEntity.class);
        deviceTypeSub
            .select(host.get("ip"))
            .where(
                cb.and(
                    cb.equal(host.get("file").get("id"), fileId),
                    host.get("deviceType").in(params.getDeviceTypes())));

        predicates.add(
            cb.or(
                root.get("srcIp").in(deviceTypeSub),
                root.get("dstIp").in(deviceTypeSub)));
      }

      // Country filter — srcIp or dstIp resolves to one of the given country codes
      if (params.getCountries() != null && !params.getCountries().isEmpty()) {
        Subquery<String> countrySub = query.subquery(String.class);
        var geo = countrySub.from(IpGeoInfoEntity.class);
        countrySub
            .select(geo.get("ip"))
            .where(geo.get("countryCode").in(params.getCountries()));
        predicates.add(
            cb.or(root.get("srcIp").in(countrySub), root.get("dstIp").in(countrySub)));
      }

      // Payload contains — EXISTS subquery: match hex-encoded payload of any packet
      if (params.getPayloadContains() != null && !params.getPayloadContains().isBlank()) {
        String hexNeedle = toHexNeedle(params.getPayloadContains());
        if (hexNeedle != null && !hexNeedle.isEmpty()) {
          Subquery<UUID> sub = query.subquery(UUID.class);
          var packet = sub.from(PacketEntity.class);
          sub.select(packet.get("conversation").get("id"))
              .where(
                  cb.and(
                      cb.equal(packet.get("conversation").get("id"), root.get("id")),
                      cb.isNotNull(packet.get("payload")),
                      cb.like(packet.get("payload"), "%" + hexNeedle + "%")));
          predicates.add(cb.exists(sub));
        }
      }

      return cb.and(predicates.toArray(new Predicate[0]));
    };
  }

  /**
   * Converts a user-supplied payload pattern to a lowercase hex substring for LIKE matching.
   *
   * <ul>
   *   <li>Inputs starting with {@code 0x}, or containing only hex chars plus spaces/colons, are
   *       treated as hex (separators stripped).
   *   <li>All other inputs are treated as ASCII and each character is converted to its two-digit hex
   *       equivalent.
   * </ul>
   */
  static String toHexNeedle(String input) {
    if (input == null) return null;
    String trimmed = input.trim();
    if (trimmed.isEmpty()) return null;

    // Explicit hex prefix
    if (trimmed.toLowerCase().startsWith("0x")) {
      return trimmed.substring(2).replaceAll("[\\s:\\-]", "").toLowerCase();
    }

    // Looks like space-, colon-, or hyphen-separated hex bytes (e.g. "47 45 54" or "47:45:54")
    if (trimmed.matches("[0-9a-fA-F]{2}([\\s:-][0-9a-fA-F]{2})*")) {
      return trimmed.replaceAll("[\\s:-]", "").toLowerCase();
    }

    // ASCII: convert each character to two-digit hex
    StringBuilder sb = new StringBuilder(trimmed.length() * 2);
    for (char c : trimmed.toCharArray()) {
      sb.append(String.format("%02x", (int) c));
    }
    return sb.toString();
  }
}
