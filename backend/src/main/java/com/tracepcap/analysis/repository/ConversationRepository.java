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
   * Returns at-risk conversations for a file, capped to a limit, ordered by risk count then bytes.
   * Uses native query because JPQL cannot express array_length.
   */
  @Query(
      value =
          "SELECT * FROM conversations WHERE file_id = :fileId"
              + " AND flow_risks IS NOT NULL AND array_length(flow_risks, 1) > 0"
              + " ORDER BY array_length(flow_risks, 1) DESC, total_bytes DESC"
              + " LIMIT :lim",
      nativeQuery = true)
  List<ConversationEntity> findAtRiskByFileIdLimited(
      @Param("fileId") UUID fileId, @Param("lim") int lim);

  /**
   * Returns the top-N at-risk conversations for a file, ordered by risk count descending then
   * bytes descending. Used for guaranteed risk-slot selection in story prompt construction.
   */
  @Query(
      value =
          "SELECT * FROM conversations WHERE file_id = :fileId"
              + " AND flow_risks IS NOT NULL AND array_length(flow_risks, 1) > 0"
              + " ORDER BY array_length(flow_risks, 1) DESC, total_bytes DESC"
              + " LIMIT :lim",
      nativeQuery = true)
  List<ConversationEntity> findTopAtRiskByFileId(
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

  /** Aggregated application stats (appName, packetCount, bytes) for a file. */
  @Query(
      "SELECT c.appName, SUM(c.packetCount), SUM(c.totalBytes) FROM ConversationEntity c"
          + " WHERE c.file.id = :fileId AND c.appName IS NOT NULL AND c.appName <> ''"
          + " GROUP BY c.appName ORDER BY SUM(c.totalBytes) DESC")
  List<Object[]> findApplicationStatsByFileId(@Param("fileId") UUID fileId);

  /** Aggregated L7 protocol stats (tsharkProtocol, packetCount, bytes) for a file. */
  @Query(
      "SELECT c.tsharkProtocol, SUM(c.packetCount), SUM(c.totalBytes) FROM ConversationEntity c"
          + " WHERE c.file.id = :fileId"
          + " AND c.tsharkProtocol IS NOT NULL AND c.tsharkProtocol <> ''"
          + " GROUP BY c.tsharkProtocol ORDER BY SUM(c.totalBytes) DESC")
  List<Object[]> findL7ProtocolStatsByFileId(@Param("fileId") UUID fileId);

  /**
   * Lightweight edge data for topology diagrams. Returns (srcIp, dstIp, protocol, sumBytes,
   * sumPackets), ordered by sumBytes DESC.
   */
  @Query(
      "SELECT c.srcIp, c.dstIp, c.protocol, SUM(c.totalBytes), SUM(c.packetCount)"
          + " FROM ConversationEntity c WHERE c.file.id = :fileId"
          + " GROUP BY c.srcIp, c.dstIp, c.protocol ORDER BY SUM(c.totalBytes) DESC")
  List<Object[]> findEdgeDataForDiagramByFileId(@Param("fileId") UUID fileId, Pageable pageable);

  /** Conversations that have TLS metadata (JA3 hashes or certificate info). */
  @Query(
      "SELECT c FROM ConversationEntity c WHERE c.file.id = :fileId"
          + " AND (c.ja3Client IS NOT NULL OR c.tlsIssuer IS NOT NULL"
          + " OR c.tlsSubject IS NOT NULL)"
          + " ORDER BY c.totalBytes DESC")
  List<ConversationEntity> findConversationsWithTlsByFileId(
      @Param("fileId") UUID fileId, Pageable pageable);

  /** Distinct HTTP user-agent strings seen in a file (unnested from array column). */
  @Query(
      value =
          "SELECT DISTINCT unnest(http_user_agents) AS ua"
              + " FROM conversations WHERE file_id = :fileId"
              + " AND http_user_agents IS NOT NULL"
              + " AND array_length(http_user_agents, 1) > 0"
              + " ORDER BY ua",
      nativeQuery = true)
  List<String> findDistinctHttpUserAgentsByFileId(@Param("fileId") UUID fileId);

  /** Per-protocol total conversation count vs. at-risk count for a file. */
  @Query(
      value =
          "SELECT protocol, COUNT(*) AS total,"
              + " SUM(CASE WHEN flow_risks IS NOT NULL AND array_length(flow_risks,1) > 0"
              + "     THEN 1 ELSE 0 END) AS at_risk"
              + " FROM conversations WHERE file_id = :fileId"
              + " GROUP BY protocol ORDER BY total DESC",
      nativeQuery = true)
  List<Object[]> findProtocolRiskMatrixByFileId(@Param("fileId") UUID fileId);

  /** Count of conversations with no detected application name for a file. */
  @Query(
      value =
          "SELECT COUNT(*) FROM conversations"
              + " WHERE file_id = :fileId AND (app_name IS NULL OR app_name = '')",
      nativeQuery = true)
  long countUnknownAppByFileId(@Param("fileId") UUID fileId);

  /** Total packet count across all conversations for a file. */
  @Query(
      "SELECT COALESCE(SUM(c.packetCount), 0) FROM ConversationEntity c"
          + " WHERE c.file.id = :fileId")
  long sumPacketsByFileId(@Param("fileId") UUID fileId);

  /** All conversations for a file that have TLS certificate data (for anomaly aggregation). */
  @Query(
      "SELECT c FROM ConversationEntity c WHERE c.file.id = :fileId"
          + " AND c.tlsIssuer IS NOT NULL")
  List<ConversationEntity> findTlsConversationsByFileId(@Param("fileId") UUID fileId);

  /**
   * Returns flow tuples (srcIp, dstIp, dstPort, protocol, appName, startTime) for groups that
   * have at least 3 conversations, ordered for efficient beacon detection grouping.
   */
  @Query(
      value =
          "SELECT src_ip, dst_ip, dst_port, protocol, app_name, start_time"
              + " FROM conversations"
              + " WHERE file_id = :fileId"
              + "   AND (src_ip, COALESCE(dst_ip,''), COALESCE(CAST(dst_port AS text),''), protocol) IN ("
              + "     SELECT src_ip, COALESCE(dst_ip,''), COALESCE(CAST(dst_port AS text),''), protocol"
              + "     FROM conversations WHERE file_id = :fileId"
              + "     GROUP BY src_ip, dst_ip, dst_port, protocol HAVING COUNT(*) >= 3"
              + "   )"
              + " ORDER BY src_ip, dst_ip, dst_port, protocol, start_time",
      nativeQuery = true)
  List<Object[]> findFlowsForBeaconDetection(@Param("fileId") UUID fileId);

  /** Returns the distinct risk type strings present across all at-risk conversations for a file. */
  @Query(
      value =
          "SELECT DISTINCT unnest(flow_risks) AS risk_type"
              + " FROM conversations WHERE file_id = :fileId"
              + " AND flow_risks IS NOT NULL AND array_length(flow_risks, 1) > 0"
              + " ORDER BY risk_type",
      nativeQuery = true)
  List<String> findDistinctRiskTypesByFileId(@Param("fileId") UUID fileId);

  /**
   * For each distinct risk type in the file, returns aggregate stats:
   * [risk_type, conversation_count, total_bytes, distinct_src_ips, distinct_dst_ips].
   * Used to build risk-type cluster summaries for the story prompt.
   */
  @Query(
      value =
          "SELECT r.risk_type,"
              + "  COUNT(*) AS conv_count,"
              + "  SUM(c.total_bytes) AS total_bytes,"
              + "  COUNT(DISTINCT c.src_ip) AS distinct_src_ips,"
              + "  COUNT(DISTINCT c.dst_ip) AS distinct_dst_ips"
              + " FROM conversations c,"
              + "   unnest(c.flow_risks) AS r(risk_type)"
              + " WHERE c.file_id = :fileId"
              + "   AND c.flow_risks IS NOT NULL AND array_length(c.flow_risks, 1) > 0"
              + " GROUP BY r.risk_type"
              + " ORDER BY conv_count DESC",
      nativeQuery = true)
  List<Object[]> findRiskTypeStatsByFileId(@Param("fileId") UUID fileId);

  /**
   * Returns the single highest-bytes conversation that contains the given risk type.
   * Used for diversity-aware example selection in story prompt construction.
   */
  @Query(
      value =
          "SELECT * FROM conversations"
              + " WHERE file_id = :fileId"
              + "   AND flow_risks IS NOT NULL"
              + "   AND :riskType = ANY(flow_risks)"
              + " ORDER BY total_bytes DESC"
              + " LIMIT 1",
      nativeQuery = true)
  List<ConversationEntity> findTopConversationByRiskType(
      @Param("fileId") UUID fileId, @Param("riskType") String riskType);

  /** Returns the distinct custom signature rule names triggered for a file. */
  @Query(
      value =
          "SELECT DISTINCT unnest(custom_signatures) AS rule_name"
              + " FROM conversations WHERE file_id = :fileId"
              + " AND custom_signatures IS NOT NULL AND array_length(custom_signatures, 1) > 0"
              + " ORDER BY rule_name",
      nativeQuery = true)
  List<String> findDistinctCustomSignaturesByFileId(@Param("fileId") UUID fileId);

  /**
   * Returns fan-out candidates: source IPs connecting to more than 5 distinct destination IPs.
   * Columns: [src_ip, distinct_dst_ips, total_flows]
   */
  @Query(
      value =
          "SELECT src_ip, COUNT(DISTINCT dst_ip) AS distinct_dst_ips, COUNT(*) AS total_flows"
              + " FROM conversations WHERE file_id = :fileId"
              + " GROUP BY src_ip HAVING COUNT(DISTINCT dst_ip) > 5"
              + " ORDER BY distinct_dst_ips DESC",
      nativeQuery = true)
  List<Object[]> findFanOutCandidatesByFileId(@Param("fileId") UUID fileId);

  /**
   * Returns top senders by total bytes for volume anomaly detection.
   * Columns: [src_ip, total_bytes, flow_count]
   */
  @Query(
      value =
          "SELECT src_ip, SUM(total_bytes) AS total_bytes, COUNT(*) AS flow_count"
              + " FROM conversations WHERE file_id = :fileId"
              + " GROUP BY src_ip ORDER BY total_bytes DESC LIMIT 20",
      nativeQuery = true)
  List<Object[]> findTopSendersByFileId(@Param("fileId") UUID fileId);

  /**
   * Returns long-duration sessions exceeding the given threshold in seconds.
   * Columns: [src_ip, dst_ip, dst_port, protocol, app_name, duration_ms, total_bytes, packet_count]
   */
  @Query(
      value =
          "SELECT src_ip, dst_ip, dst_port, protocol, app_name,"
              + " EXTRACT(EPOCH FROM (end_time - start_time)) * 1000 AS duration_ms,"
              + " total_bytes, packet_count"
              + " FROM conversations WHERE file_id = :fileId"
              + "   AND EXTRACT(EPOCH FROM (end_time - start_time)) > :thresholdSeconds"
              + " ORDER BY duration_ms DESC LIMIT 20",
      nativeQuery = true)
  List<Object[]> findLongSessionsByFileId(
      @Param("fileId") UUID fileId, @Param("thresholdSeconds") long thresholdSeconds);

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

      // L7 Protocol multi-value — plain SARGable IN predicate.
      // Filter values arrive already normalised (uppercase, "THE " stripped) from the badge labels.
      // For backward-compatibility with data stored before normalisation was introduced, we expand
      // each value to its common pre-normalisation variants on the Java side so no DB-side function
      // is applied to the column and any index on tshark_protocol remains usable.
      if (params.getL7Protocols() != null && !params.getL7Protocols().isEmpty()) {
        List<String> variants =
            params.getL7Protocols().stream()
                .filter(p -> p != null && !p.isEmpty())
                .flatMap(
                    p -> {
                      String titleCase =
                          Character.toUpperCase(p.charAt(0)) + p.substring(1).toLowerCase();
                      return java.util.stream.Stream.of(
                          p, titleCase, p.toLowerCase(), "The " + titleCase);
                    })
                .distinct()
                .collect(java.util.stream.Collectors.toList());
        predicates.add(root.get("tsharkProtocol").in(variants));
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
            cb.or(root.get("srcIp").in(deviceTypeSub), root.get("dstIp").in(deviceTypeSub)));
      }

      // Country filter — srcIp or dstIp resolves to one of the given country codes
      if (params.getCountries() != null && !params.getCountries().isEmpty()) {
        Subquery<String> countrySub = query.subquery(String.class);
        var geo = countrySub.from(IpGeoInfoEntity.class);
        countrySub.select(geo.get("ip")).where(geo.get("countryCode").in(params.getCountries()));
        predicates.add(cb.or(root.get("srcIp").in(countrySub), root.get("dstIp").in(countrySub)));
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
   *   <li>All other inputs are treated as ASCII and each character is converted to its two-digit
   *       hex equivalent.
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
