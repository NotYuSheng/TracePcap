package com.tracepcap.subnets.dto;

import java.time.LocalDateTime;
import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SubnetDefinitionDto {
  private Long id;
  private String cidr;
  private String label;
  private String description;
  private String source;
  private boolean confirmed;
  private Integer hostCount;       // populated only for detect results
  private Double densityScore;     // observed hosts / subnet capacity (0–1)
  private Integer snapshotsSeen;   // cross-snapshot consensus fields
  private Integer totalSnapshots;
  private LocalDateTime labeledAt; // when the label was last confirmed (staleness baseline time)
  private LocalDateTime staleSince; // null = not stale
  private List<String> staleFields; // what drifted since the label baseline
  /** "default", or "network" for a network's own entry (#915 phase 4); null on the default list. */
  private String scope;
  /** The network's entry hides the default's subnet for this CIDR. */
  private boolean hidden;
  /** A network entry for a CIDR the default also has. */
  private boolean overridesDefault;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
}
