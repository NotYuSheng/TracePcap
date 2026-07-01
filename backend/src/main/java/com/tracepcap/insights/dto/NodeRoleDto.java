package com.tracepcap.insights.dto;

import java.time.LocalDateTime;
import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class NodeRoleDto {
  private String entityType;
  private String entityKey;
  private String roleLabel;
  private String roleDescription;
  private boolean llmSuggested;
  private boolean confirmedByHuman;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;

  // Staleness (#369): null staleSince = label still considered current.
  private LocalDateTime labeledAt;
  private LocalDateTime staleSince;
  private List<String> staleFields;
}
