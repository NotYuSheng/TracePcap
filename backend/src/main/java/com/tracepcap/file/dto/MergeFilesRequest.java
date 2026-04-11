package com.tracepcap.file.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.UUID;
import lombok.Data;

/** Request body for merging multiple PCAP files */
@Data
public class MergeFilesRequest {

  @NotEmpty(message = "At least two file IDs are required")
  @Size(min = 2, message = "At least two file IDs are required")
  private List<UUID> fileIds;

  /** Optional user-supplied name for the merged file (without extension). */
  private String mergedFileName;
}
