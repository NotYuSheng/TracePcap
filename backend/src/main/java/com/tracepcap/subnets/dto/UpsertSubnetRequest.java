package com.tracepcap.subnets.dto;

import java.util.UUID;
import lombok.Data;

@Data
public class UpsertSubnetRequest {
  private String cidr;
  private String label;
  private String description;
  private boolean confirmed;

  /**
   * Optional Monitor network context. When present and the label is confirmed, the subnet's
   * composition baseline is captured from this network's latest snapshot for staleness detection.
   */
  private UUID networkId;
}
