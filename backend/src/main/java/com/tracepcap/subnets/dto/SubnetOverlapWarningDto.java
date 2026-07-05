package com.tracepcap.subnets.dto;

import java.util.List;
import lombok.Builder;
import lombok.Data;

/**
 * Evidence that a CIDR may actually be two different L2 networks sharing the same range (#461). The
 * tell is a member IP claimed by more than one MAC within a single capture — there is no benign
 * reason for two devices to answer for the same IP at once. Absent this signal, no warning is
 * produced (overlaps are otherwise indistinguishable from capture data alone).
 */
@Data
@Builder
public class SubnetOverlapWarningDto {
  private Long subnetId;
  private String cidr;

  /** An in-range IP observed with multiple MACs. */
  private String conflictingIp;

  /** The distinct MACs seen claiming {@code conflictingIp} — each a candidate separate device. */
  private List<String> macs;
}
