package com.tracepcap.subnets.dto;

import lombok.Builder;
import lombok.Data;

/**
 * An AI-suggested label + description for a subnet, inferred from the behaviour of its member nodes
 * (#363). Not persisted — the analyst reviews it in the edit form and saves it onto the subnet
 * definition's own {@code label}/{@code description} fields.
 */
@Data
@Builder
public class SubnetLabelSuggestionDto {
  /** Short subnet name, e.g. "IoT sensor cluster". */
  private String label;

  /** Longer description: purpose reasoning, key observations, anomalies. */
  private String description;

  /** How many member nodes the suggestion was based on. */
  private int memberCount;

  /** How many snapshots were scanned. */
  private int snapshotCount;
}
