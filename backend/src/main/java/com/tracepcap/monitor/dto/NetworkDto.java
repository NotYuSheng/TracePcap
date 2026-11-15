package com.tracepcap.monitor.dto;

import java.time.LocalDateTime;
import java.util.UUID;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class NetworkDto {
  private UUID id;
  private String name;
  private String description;
  private int snapshotCount;
  private long criticalChanges;
  private long warningChanges;
  private boolean hasInsights;
  /**
   * Each capture in order, for the networks table's track: when it was captured and the most
   * severe change it brought (NONE for none; the first is the baseline).
   */
  private java.util.List<CaptureMark> captures;

  /** One capture of a network, as the networks table draws it. */
  public record CaptureMark(
      UUID snapshotId, String fileName, LocalDateTime capturedAt, boolean baseline, String changes) {}
  /** Per-network settings (#488): the inactivity rule the drift panels apply. */
  private NetworkSettingsDto settings;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
}
