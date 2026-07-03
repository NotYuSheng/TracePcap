package com.tracepcap.insights.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class NodeRoleDto {
  private UUID fileId;
  private String entityType;
  private String entityKey;
  private String roleLabel;
  private String roleDescription;
  private String origin; // MANUAL | AI | CARRIED_FORWARD
  private boolean llmSuggested;
  private boolean confirmedByHuman;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;

  // Staleness (#369): null staleSince = label still consistent with this snapshot.
  private LocalDateTime staleSince;
  private List<String> staleFields;
}
