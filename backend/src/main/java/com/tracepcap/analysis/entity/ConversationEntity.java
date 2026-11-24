package com.tracepcap.analysis.entity;

import com.tracepcap.file.entity.FileEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "conversations")
@Getter
@Setter
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConversationEntity {

  public static final int APP_NAME_MAX_LENGTH = 50;
  public static final int CATEGORY_MAX_LENGTH = 50;
  public static final int HOSTNAME_MAX_LENGTH = 255;
  public static final int JA3_HASH_LENGTH = 32;
  public static final int JA4_MAX_LENGTH = 36;
  public static final int TLS_VERSION_MAX_LENGTH = 16;
  public static final int PROTOCOL_MAX_LENGTH = 100;
  public static final int SURICATA_ALERT_MAX_LENGTH = 512;

  @EqualsAndHashCode.Include
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ToString.Exclude
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "file_id", nullable = false)
  private FileEntity file;

  @Column(name = "src_ip", nullable = false, length = 45)
  private String srcIp;

  @Column(name = "src_port")
  private Integer srcPort;

  @Column(name = "dst_ip", nullable = false, length = 45)
  private String dstIp;

  @Column(name = "dst_port")
  private Integer dstPort;

  /**
   * The endpoint that opened the connection — sent SYN without ACK (#496).
   *
   * <p>Not {@code srcIp}: conversation keys are normalised so A→B and B→A share a row, so srcIp is
   * whichever endpoint sorted first, not who started it. Null means <em>unknown</em> (no handshake
   * in this protocol, or the capture joined mid-flow), never "nobody initiated". MEASURED.
   */
  @Column(name = "initiator_ip", length = 45)
  private String initiatorIp;

  /** Each side's MAC (#462): the machine, or for outside traffic the site's router. */
  @Column(name = "src_mac", length = 50)
  private String srcMac;

  @Column(name = "dst_mac", length = 50)
  private String dstMac;

  /**
   * How the TCP connection went (#1233): ANSWERED, NO_ANSWER or REJECTED, from the handshake
   * ({@link com.tracepcap.analysis.service.TcpHandshake}). Null when unknown: not TCP, or the
   * capture joined after the SYN.
   */
  @Column(name = "connection_outcome", length = 16)
  private String connectionOutcome;

  /**
   * TCP or UDP (or the protocol for portless traffic): what the conversation is keyed on, and what
   * a detection rule's {@code protocol} means. {@link #protocol} is the display label instead
   * ("TLSV1.2"). Null for captures analysed before it was kept.
   */
  @Column(name = "transport", length = 20)
  private String transport;

  @Column(name = "initiator_port")
  private Integer initiatorPort;

  @Column(nullable = false, length = PROTOCOL_MAX_LENGTH)
  private String protocol;

  @Column(name = "app_name", length = APP_NAME_MAX_LENGTH)
  private String appName;

  @Column(name = "tshark_protocol", length = APP_NAME_MAX_LENGTH)
  private String tsharkProtocol;

  @Column(name = "flow_risks", columnDefinition = "text[]")
  private String[] flowRisks;

  @Column(name = "custom_signatures", columnDefinition = "text[]")
  private String[] customSignatures;

  @Column(name = "suricata_alerts", columnDefinition = "text[]")
  private String[] suricataAlerts;

  @Column(name = "http_user_agents", columnDefinition = "text[]")
  private String[] httpUserAgents;

  @Column(name = "category", length = CATEGORY_MAX_LENGTH)
  private String category;

  @Column(name = "hostname", length = HOSTNAME_MAX_LENGTH)
  private String hostname;

  @Column(name = "ja3_client", length = JA3_HASH_LENGTH)
  private String ja3Client;

  @Column(name = "ja3_server", length = JA3_HASH_LENGTH)
  private String ja3Server;

  /** JA4 client fingerprint (#599), from nDPI 6, e.g. {@code t13d1516h2_8daaf6152771_02713d6af862}. */
  @Column(name = "ja4_client", length = JA4_MAX_LENGTH)
  private String ja4Client;

  /** Negotiated TLS version (#599), from Suricata, e.g. {@code "TLS 1.2"}. */
  @Column(name = "tls_version", length = TLS_VERSION_MAX_LENGTH)
  private String tlsVersion;

  // The server certificate's detail (#1235), parsed from the DER Suricata logs. All null when the
  // certificate wasn't seen (TLS 1.3 encrypts it, or Suricata didn't run).

  /** Subject alternative names: DNS names and IPs, at most 50. */
  @Column(name = "tls_sans", columnDefinition = "text[]")
  private String[] tlsSans;

  /** RSA, EC, DSA... */
  @Column(name = "tls_key_type", length = 16)
  private String tlsKeyType;

  @Column(name = "tls_key_bits")
  private Integer tlsKeyBits;

  /** e.g. SHA256withRSA. */
  @Column(name = "tls_sig_alg", length = 64)
  private String tlsSigAlg;

  /** Issuer = subject and it verifies with its own key. */
  @Column(name = "tls_self_signed")
  private Boolean tlsSelfSigned;

  /** Certificates the server sent, leaf included. */
  @Column(name = "tls_chain_length")
  private Integer tlsChainLength;

  @Column(name = "tls_issuer", columnDefinition = "TEXT")
  private String tlsIssuer;

  @Column(name = "tls_subject", columnDefinition = "TEXT")
  private String tlsSubject;

  @Column(name = "tls_not_before")
  private LocalDateTime tlsNotBefore;

  @Column(name = "tls_not_after")
  private LocalDateTime tlsNotAfter;

  @Column(name = "packet_count", nullable = false)
  @Builder.Default
  private Long packetCount = 0L;

  @Column(name = "total_bytes", nullable = false)
  @Builder.Default
  private Long totalBytes = 0L;

  @Column(name = "start_time", nullable = false)
  private LocalDateTime startTime;

  @Column(name = "end_time", nullable = false)
  private LocalDateTime endTime;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;
}
