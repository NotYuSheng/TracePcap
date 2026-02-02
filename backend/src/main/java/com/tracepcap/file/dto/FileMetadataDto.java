package com.tracepcap.file.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** DTO for file metadata */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FileMetadataDto {

  private String fileId;

  private String fileName;

  private Long fileSize;

  @JsonFormat(shape = JsonFormat.Shape.NUMBER)
  private LocalDateTime uploadedAt;

  private String status;

  private Integer packetCount;

  private Long duration;

  @JsonFormat(shape = JsonFormat.Shape.NUMBER)
  private LocalDateTime startTime;

  @JsonFormat(shape = JsonFormat.Shape.NUMBER)
  private LocalDateTime endTime;
}
