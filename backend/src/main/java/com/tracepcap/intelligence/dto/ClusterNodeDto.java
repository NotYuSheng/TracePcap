package com.lanturn.intelligence.dto;

import java.util.List;
import java.util.Map;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClusterNodeDto {
  private String id;
  private String label;
  private String groupType;
  private long hostCount;
  private long totalBytes;
  private long totalPackets;
  private long conversationCount;
  private long riskCount;
  private List<String> dominantProtocols;
  private List<String> sampleIps;
  private List<String> topRiskTypes;
  private Map<String, Long> ipBytes;
  private Map<String, Long> ipConversations;
  private Map<String, Long> ipRisks;
  private Map<String, Long> ipPeers;
  /** Approximate latitude of this cluster's location (city/country centroid). Null if not geo-based. */
  private Double lat;
  /** Approximate longitude of this cluster's location (city/country centroid). Null if not geo-based. */
  private Double lon;
  /** Source of geo data for this cluster: "ipinfo" or "mmdb". Null if not a geo-based grouping. */
  private String geoSource;
}
