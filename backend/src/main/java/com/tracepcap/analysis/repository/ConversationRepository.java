package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.PacketEntity;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Subquery;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
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

  void deleteByFileId(UUID fileId);

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

      // Protocol multi-value
      if (params.getProtocols() != null && !params.getProtocols().isEmpty()) {
        predicates.add(root.get("protocol").in(params.getProtocols()));
      }

      // Application multi-value
      if (params.getApps() != null && !params.getApps().isEmpty()) {
        predicates.add(root.get("appName").in(params.getApps()));
      }

      // Category multi-value
      if (params.getCategories() != null && !params.getCategories().isEmpty()) {
        predicates.add(root.get("category").in(params.getCategories()));
      }

      // Has flow risks
      if (Boolean.TRUE.equals(params.getHasRisks())) {
        predicates.add(cb.isNotNull(root.get("flowRisks")));
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

      return cb.and(predicates.toArray(new Predicate[0]));
    };
  }
}
