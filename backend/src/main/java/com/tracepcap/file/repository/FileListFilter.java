package com.tracepcap.file.repository;

import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.entity.FileEntity.FileSource;
import com.tracepcap.file.entity.FileEntity.FileStatus;
import jakarta.persistence.criteria.Predicate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.data.jpa.domain.Specification;

/**
 * Narrows the captures list. Every field is optional; an empty filter lists everything. The home
 * page's chips are built from these: "Kept with a network" is {@code fileIds}, "Expiring soon" is
 * an uploaded-before cut-off with the kept ones excluded, "Failed" is a status.
 */
public record FileListFilter(
    FileSource source,
    String search,
    Collection<FileStatus> statuses,
    Collection<UUID> fileIds,
    Collection<UUID> excludeFileIds,
    LocalDateTime uploadedBefore) {

  public static FileListFilter ofSource(FileSource source) {
    return new FileListFilter(source, null, null, null, null, null);
  }

  public Specification<FileEntity> toSpecification() {
    return (root, query, cb) -> {
      List<Predicate> where = new ArrayList<>();
      if (source != null) where.add(cb.equal(root.get("source"), source));
      if (search != null && !search.isBlank()) {
        String like = "%" + search.trim().toLowerCase(Locale.ROOT).replace("%", "\\%").replace("_", "\\_") + "%";
        where.add(cb.like(cb.lower(root.get("fileName")), like, '\\'));
      }
      if (statuses != null && !statuses.isEmpty()) where.add(root.get("status").in(statuses));
      if (fileIds != null) {
        // An explicit empty list means "none of them": nothing matches.
        where.add(fileIds.isEmpty() ? cb.disjunction() : root.get("id").in(fileIds));
      }
      if (excludeFileIds != null && !excludeFileIds.isEmpty()) {
        where.add(cb.not(root.get("id").in(excludeFileIds)));
      }
      if (uploadedBefore != null) where.add(cb.lessThan(root.get("uploadedAt"), uploadedBefore));
      return cb.and(where.toArray(Predicate[]::new));
    };
  }
}
