package com.tracepcap.analysis.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConversationResponse {

  /** Geolocation info for a single IP endpoint. Null for private/unresolved IPs. */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class GeoInfo {
    private String country;
    private String countryCode;
    private String asn;
    private String org;
    private String geoSource;
  }

  private UUID conversationId;
  private String srcIp;
  private Integer srcPort;
  private String dstIp;
  private Integer dstPort;

  /**
   * The endpoint that opened the connection — sent SYN without ACK (#496).
   *
   * <p>Not {@code srcIp}, which is only "whichever endpoint sorted first" once A→B and B→A are
   * normalised into one conversation. Null means <em>unknown</em> (no handshake, or the capture
   * joined mid-flow), never "nobody initiated" — and must not be inferred from port numbers.
   */
  private String initiatorIp;

  private Integer initiatorPort;

  private String protocol;
  private String appName;
  private String tsharkProtocol;
  private String category;
  private String hostname;
  private String ja3Client;
  private String ja3Server;
  private String tlsIssuer;
  private String tlsSubject;
  private LocalDateTime tlsNotBefore;
  private LocalDateTime tlsNotAfter;
  private List<String> flowRisks;
  private List<String> customSignatures;
  private List<String> suricataAlerts;
  private List<String> httpUserAgents;
  private List<String> detectedFileTypes;
  private Long packetCount;
  private Long totalBytes;
  private LocalDateTime startTime;
  private LocalDateTime endTime;
  private Long durationMs;
  private GeoInfo srcGeo;
  private GeoInfo dstGeo;
}
