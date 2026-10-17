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

  /** Size (MB, rounded up) of the JSON string that tripped Jackson's max-string-length guard. */
  private Integer attemptedSizeMb;

  /**
   * APP_MEMORY_MB to set so this request's payload fits under the derived JSON string cap (see
   * JacksonConfig, backend/docker-entrypoint.sh). Null when raising it would not help — the
   * request exceeds JACKSON_MAX_STRING_MB's hard ceiling regardless of memory budget.
   */
  private Integer recommendedAppMemoryMb;

  /** Per-field validation messages, present only on 400 validation failures. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private Map<String, String> validationErrors;
}
