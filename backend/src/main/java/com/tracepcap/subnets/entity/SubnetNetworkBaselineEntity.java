package com.tracepcap.subnets.entity;

import jakarta.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * A subnet's staleness baseline in one network (#363, per network since #915 phase 4): the
 * composition (dominant member device types + protocols) when an analyst confirmed its label,
 * compared against each new snapshot of that network.
 */
@Entity
@Table(name = "subnet_network_baselines")
@IdClass(SubnetNetworkBaselineEntity.Key.class)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SubnetNetworkBaselineEntity {

  @Id
  @Column(name = "subnet_id")
  private Long subnetId;

  @Id
  @Column(name = "network_id")
  private UUID networkId;

  @Column(name = "labeled_at")
  private LocalDateTime labeledAt;

  @Column(name = "baseline_file_id")
  private UUID baselineFileId;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "baseline_composition", columnDefinition = "jsonb")
  private Map<String, Object> baselineComposition;

  @Column(name = "stale_since")
  private LocalDateTime staleSince;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "stale_fields", columnDefinition = "jsonb")
  private List<String> staleFields;

  @EqualsAndHashCode
  @NoArgsConstructor
  @AllArgsConstructor
  @Getter
  @Setter
  public static class Key implements Serializable {
    private Long subnetId;
    private UUID networkId;
  }
}
