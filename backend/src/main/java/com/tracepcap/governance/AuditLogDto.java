package com.tracepcap.governance;

import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** One audited change (#915): who, when, what, and the value before and after. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLogDto {
  private Long id;
  private LocalDateTime at;
  /** The login's username, or {@code system} when login is off. */
  private String actor;
  private String action;
  private String targetType;
  private String targetId;
  private Object before;
  private Object after;
}
