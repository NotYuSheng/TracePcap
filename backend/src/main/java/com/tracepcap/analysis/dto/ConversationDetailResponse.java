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
