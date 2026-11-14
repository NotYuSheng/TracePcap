package com.tracepcap.governance;

import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.config.security.CurrentActor;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writes and reads the audit log (#915).
 *
 * <p>{@link #record} joins the caller's transaction on purpose: the entry commits with the change
 * it describes, or neither does. A change must never land unaudited.
 */
@Service
@RequiredArgsConstructor
public class AuditLogService {

  static final int MAX_PAGE_SIZE = 200;

  private final AuditLogRepository repository;
  private final CurrentActor currentActor;
  private final ObjectMapper objectMapper;

  /**
   * Records a change by the current caller. {@code before} and {@code after} are any
   * JSON-serialisable values (usually the DTO); null means "didn't exist" or "removed".
   */
  @Transactional(propagation = Propagation.MANDATORY)
  public void record(String action, String targetType, String targetId, Object before, Object after) {
    repository.save(
        AuditLogEntity.builder()
            .at(LocalDateTime.now())
            .actor(currentActor.username())
            .action(action)
            .targetType(targetType)
            .targetId(targetId)
            .before(toJson(before))
            .after(toJson(after))
            .build());
  }

  @Transactional(readOnly = true)
  public PagedResponse<AuditLogDto> list(int page, int pageSize, String search) {
    return list(page, pageSize, search, null);
  }

  /** {@code targetTypes} limits the list to entries about those kinds of thing; null or empty: all. */
  @Transactional(readOnly = true)
  public PagedResponse<AuditLogDto> list(int page, int pageSize, String search, java.util.List<String> targetTypes) {
    if (page < 1) throw new IllegalArgumentException("page must be 1 or more");
    if (pageSize < 1 || pageSize > MAX_PAGE_SIZE) {
      throw new IllegalArgumentException("pageSize must be between 1 and " + MAX_PAGE_SIZE);
    }
    String q =
        search == null || search.isBlank()
            ? null
            : "%" + search.trim().toLowerCase(Locale.ROOT).replace("%", "\\%").replace("_", "\\_") + "%";
    Page<AuditLogEntity> result =
        targetTypes == null || targetTypes.isEmpty()
            ? repository.search(q, PageRequest.of(page - 1, pageSize))
            : repository.searchIn(q, targetTypes, PageRequest.of(page - 1, pageSize));
    return PagedResponse.of(
        result.getContent().stream().map(AuditLogService::toDto).toList(),
        result.getTotalElements(),
        page,
        pageSize);
  }

  /**
   * Stores a plain JSON object, so a later change to a DTO class can't break reading old rows. A
   * value that isn't an object (a string, a list) is wrapped as {@code {"value": ...}}.
   */
  @SuppressWarnings("unchecked")
  private Map<String, Object> toJson(Object value) {
    if (value == null) return null;
    Object tree = objectMapper.convertValue(value, Object.class);
    return tree instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of("value", tree);
  }

  private static AuditLogDto toDto(AuditLogEntity e) {
    return AuditLogDto.builder()
        .id(e.getId())
        .at(e.getAt())
        .actor(e.getActor())
        .action(e.getAction())
        .targetType(e.getTargetType())
        .targetId(e.getTargetId())
        .before(e.getBefore())
        .after(e.getAfter())
        .build();
  }
}
