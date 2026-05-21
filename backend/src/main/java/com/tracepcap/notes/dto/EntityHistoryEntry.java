package com.lanturn.notes.dto;

import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EntityHistoryEntry {
  private String fileId;
  private String fileName;
  private LocalDateTime startTime;
  private LocalDateTime endTime;
  private Long packetCount;
  private Long totalBytes;
}
