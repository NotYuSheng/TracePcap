package com.tracepcap.analysis.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Authoritative aggregate stats for an APPLICATION or PROTOCOL entity across <em>all</em> matching
 * conversations in a file (not a single page). Backs the EntityDetailModal stats panel (#436).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EntityStatsResponse {

  /** A single peer IP and the total bytes it accounts for across matching conversations. */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class TopPeer {
    private String ip;
    private long bytes;
  }

  /** Number of matching conversations. */
  private long conversationCount;

  /** Total packets across all matching conversations. */
  private long packetCount;

  /** Total bytes across all matching conversations. */
  private long totalBytes;

  /** Top peer IPs by total bytes (both endpoints counted), capped server-side. */
  private List<TopPeer> topPeers;
}
