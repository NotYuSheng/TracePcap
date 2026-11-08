package com.tracepcap.analysis.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * An analyst's correction to where one device ends and the next begins on an address (#918 item
 * 3). Kept apart from the derived {@link IpOccupancyEntity} rows so recomputing never loses it.
 */
@Entity
@Table(name = "occupancy_decisions")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OccupancyDecisionEntity {

  /** A boundary at {@code at}, even with no MAC change. */
  public static final String SPLIT = "split";
  /** Removes the automatic boundary at {@code at}. */
  public static final String MERGE = "merge";

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 45)
  private String ip;

  @Column(nullable = false)
  private LocalDateTime at;

  @Column(nullable = false, length = 10)
  private String action;

  @Column(nullable = false, columnDefinition = "TEXT")
  private String reason;

  @Column(length = 255)
  private String actor;

  @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
  private LocalDateTime createdAt;
}
