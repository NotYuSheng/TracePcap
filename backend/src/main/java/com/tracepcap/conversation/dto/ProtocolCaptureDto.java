package com.tracepcap.conversation.dto;

import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** A capture an nDPI application name appears in, and in how many of its conversations. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProtocolCaptureDto {
  private UUID fileId;
  private String fileName;
  private long conversations;
}
