package com.tracepcap.file.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Response DTO for file upload */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FileUploadResponse {

  private String fileId;

  private String fileName;

  private Long fileSize;

  @JsonFormat(shape = JsonFormat.Shape.NUMBER)
  private LocalDateTime uploadedAt;

  private String status;

  private String storageLocation;
}
