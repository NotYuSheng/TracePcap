package com.tracepcap.common.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.LocalDateTime;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Standard error response DTO */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ErrorResponse {

  @JsonFormat(shape = JsonFormat.Shape.NUMBER)
  private LocalDateTime timestamp;

  private int status;

  private String error;

  private String message;

  private String path;

  private String existingFileId;

  private String errorCode;

  private String promptText;

  private Integer promptTokens;

  private Integer contextLength;

  /** Per-field validation messages, present only on 400 validation failures. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private Map<String, String> validationErrors;
}
