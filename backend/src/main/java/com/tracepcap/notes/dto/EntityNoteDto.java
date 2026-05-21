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
public class EntityNoteDto {
  private String entityType;
  private String entityKey;
  private String note;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
}
