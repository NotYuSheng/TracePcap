package com.tracepcap.monitor.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Per-network settings (#468, #488). Today that is the inactivity rule: how long a device, IP or
 * protocol can go unseen before the drift panels show it as "no longer seen" rather than "quiet".
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkSettingsDto {

  public enum InactivityMode {
    /** Gone once missing from the last {@code inactivityThreshold} captures. */
    SNAPSHOTS,
    /** Gone once not seen for more than {@code inactivityThreshold} days, from the latest capture. */
    DAYS
  }

  public static final InactivityMode DEFAULT_MODE = InactivityMode.SNAPSHOTS;
  public static final int DEFAULT_THRESHOLD = 1;

  @NotNull private InactivityMode inactivityMode;

  /** A capture count for SNAPSHOTS, a day count for DAYS. */
  @NotNull
  @Min(1)
  @Max(3650)
  private Integer inactivityThreshold;
}
