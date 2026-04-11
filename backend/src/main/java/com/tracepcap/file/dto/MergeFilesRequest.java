package com.tracepcap.file.dto;

import java.util.List;
import java.util.UUID;
import lombok.Data;

/** Request body for merging multiple PCAP files */
@Data
public class MergeFilesRequest {

  private List<UUID> fileIds;

  /** Optional user-supplied name for the merged file (without extension). */
  private String mergedFileName;
}
