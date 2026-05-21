package com.lanturn.insights.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class NetworkInsightDto {
  private UUID id;
  private UUID networkId;
  private LocalDateTime generatedAt;
  private String modelUsed;
  private String status;
  private String errorMessage;
  private String audience;
  private String focus;

  // Parsed content fields (null when status=FAILED)
  private String summary;
  private List<NarrativeSection> narrativeSections;
  private List<Anomaly> anomalies;
  private List<Correlation> correlations;
  private List<String> recommendations;

  @Data
  @Builder
  public static class NarrativeSection {
    private String title;
    private String content;
  }

  @Data
  @Builder
  public static class Anomaly {
    private String title;
    private String description;
    private String severity;
  }

  @Data
  @Builder
  public static class Correlation {
    private String externalEvent;
    private String networkChange;
    private String explanation;
  }
}
