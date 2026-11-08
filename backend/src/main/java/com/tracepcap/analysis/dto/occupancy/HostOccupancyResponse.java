package com.tracepcap.analysis.dto.occupancy;

import java.time.LocalDateTime;
import java.util.List;
import lombok.Builder;
import lombok.Value;

/** An address's occupancies in one capture, with the analyst's decisions and split suggestions (#918). */
@Value
@Builder
public class HostOccupancyResponse {
  String ip;
  /** The IP's first and last activity in the capture. */
  LocalDateTime firstActivity;
  LocalDateTime lastActivity;
  /** Two MACs claimed the address at the same time, so nothing was split automatically. */
  boolean overlapping;
  /** A failover virtual address: shared by design, never split automatically. */
  boolean virtualAddress;
  List<Occupancy> occupancies;
  List<Decision> decisions;
  List<Suggestion> suggestions;
  boolean canEdit;
  String editReason;

  @Value
  @Builder
  public static class Occupancy {
    int idx;
    String mac;
    String hostname;
    LocalDateTime startsAt;
    LocalDateTime endsAt;
    /** arp, dhcp or manual; null for the first. */
    String startSource;
    String startEvidence;
    /** {@code startsAt} as an ISO string, to send back exactly when merging. */
    String boundaryKey;
    /** Whether the boundary starting this occupancy was found automatically (so it can be merged). */
    boolean automatic;
    long conversations;
  }

  @Value
  @Builder
  public static class Decision {
    Long id;
    LocalDateTime at;
    String action;
    String reason;
    String actor;
    LocalDateTime createdAt;
  }

  @Value
  @Builder
  public static class Suggestion {
    LocalDateTime at;
    /** {@code at} as an ISO string, to send back exactly. */
    String key;
    /** mac, dhcp or silence. */
    String kind;
    String description;
  }
}
