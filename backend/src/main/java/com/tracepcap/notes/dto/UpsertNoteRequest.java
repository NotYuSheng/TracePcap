package com.tracepcap.notes.dto;

import lombok.Data;

@Data
public class UpsertNoteRequest {
  private String entityType;
  private String entityKey;
  private String note;
}
