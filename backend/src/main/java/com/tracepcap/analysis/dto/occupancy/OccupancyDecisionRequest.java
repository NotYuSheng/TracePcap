package com.tracepcap.analysis.dto.occupancy;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.LocalDateTime;
import lombok.Data;

/** Split the address at a time, or merge away the automatic boundary at a time (#918). */
@Data
public class OccupancyDecisionRequest {
  @NotNull private LocalDateTime at;

  @NotBlank
  @Pattern(regexp = "split|merge", message = "must be split or merge")
  private String action;

  @NotBlank
  @Size(max = 1000)
  private String reason;
}
