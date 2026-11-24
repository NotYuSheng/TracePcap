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
public class ConversationDetailResponse {
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
   * joined mid-flow), never "nobody initiated".
   */
  private String initiatorIp;

  /** Each side's MAC (#462): the machine, or for outside traffic the site's router. */
  private String srcMac;

  private String dstMac;

  /** How the TCP connection went (#1233): ANSWERED, NO_ANSWER, REJECTED; null when unknown. */
  private String connectionOutcome;

  private Integer initiatorPort;
  private String protocol;
  private String appName;
  private String tsharkProtocol;
  private String category;
  private String hostname;
  private String ja3Client;
  private String ja3Server;
  /** JA4 client fingerprint, from nDPI (#599). */
  private String ja4Client;
  /** Negotiated TLS version, from Suricata (#599). */
  private String tlsVersion;

  /** The server certificate's detail and checks (#1235); null when the certificate wasn't seen. */
  private TlsCertificateDto tlsCertificate;
  private String tlsIssuer;
  private String tlsSubject;
  private LocalDateTime tlsNotBefore;
  private LocalDateTime tlsNotAfter;
  private List<String> flowRisks;
  private List<String> customSignatures;
  private List<String> suricataAlerts;

  /**
   * Each Suricata alert on this conversation as it fired (#1265), oldest first: when, which side
   * sent the packet, the rule's metadata, and the HTTP request. Empty for captures analysed before.
   */
  private List<IdsAlert> idsAlerts;

  /**
   * How many alerts fired on this conversation (#1284). More than {@code idsAlerts} holds when the
   * records stopped at their cap: those are the first. Null for captures analysed before.
   */
  private Integer idsAlertCount;

  /** Suricata's protocol anomalies on this conversation (#1268), oldest first. */
  private List<Anomaly> anomalies;

  /** One protocol anomaly: malformed or one-sided traffic, not an attack signature. */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  // Its own schema name: springdoc names schemas by simple class name, and NetworkInsightDto has an
  // Anomaly too, so the two merged into one with that one's fields.
  @io.swagger.v3.oas.annotations.media.Schema(name = "ProtocolAnomaly")
  public static class Anomaly {
    private LocalDateTime time;
    private String srcIp;
    private String type;
    private String layer;
    private String appProto;
    private String event;
  }

  /** One alert. {@code srcIp} is the side that sent the packet that fired it. */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class IdsAlert {
    private LocalDateTime time;
    private String srcIp;
    private Integer srcPort;
    private String dstIp;
    private Integer dstPort;
    private long sid;
    private Integer rev;
    private String signature;
    private String category;
    private Integer severity;
    /** The rule's own rating: Critical, Major, Minor or Informational. */
    private String signatureSeverity;
    /** The rule's own confidence: High, Medium or Low. */
    private String confidence;
    private String attackTarget;
    private String httpMethod;
    private String httpHost;
    private String httpUrl;
    private String httpUserAgent;
    private Integer httpStatus;
  }
  private List<String> httpUserAgents;
  private Long packetCount;
  private Long totalBytes;

  /** Bytes each way (#1260); null for conversations analysed before they were measured. */
  private Long bytesSrcToDst;

  private Long bytesDstToSrc;
  private LocalDateTime startTime;
  private LocalDateTime endTime;
  private Long durationMs;
  private ConversationResponse.GeoInfo srcGeo;
  private ConversationResponse.GeoInfo dstGeo;
  private List<PacketResponse> packets;
}
