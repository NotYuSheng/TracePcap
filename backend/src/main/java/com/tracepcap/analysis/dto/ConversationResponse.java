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

  /** Each side's MAC (#462): the machine, or for outside traffic the site's router. */
  private String srcMac;

  private String dstMac;

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

  /**
   * Who was logged in on each endpoint when this conversation started (#812 follow-up). Null when
   * no Windows login had been seen on that host by then. With several accounts, {@code username}
   * is null and {@code accountCount} says how many: the host's timeline has the detail.
   */
  private AccountAtTime srcAccount;
  private AccountAtTime dstAccount;

  /**
   * Fills {@link #srcAccount} / {@link #dstAccount} from the conversation's start time, using
   * logins loaded once for the whole page. Returns this, for use in a stream.
   */
  public ConversationResponse withAccountsFrom(
      com.tracepcap.analysis.spi.WindowsLogonLookup.AccountsAtTime accounts) {
    this.srcAccount = AccountAtTime.of(accounts.at(srcIp, startTime));
    this.dstAccount = AccountAtTime.of(accounts.at(dstIp, startTime));
    return this;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class AccountAtTime {
    private String username;
    private int accountCount;
    /** When that account was first seen logging in (a login, not a session start-to-end). */
    private LocalDateTime firstLoginAt;

    static AccountAtTime of(com.tracepcap.analysis.spi.WindowsLogonLookup.UserAtTime u) {
      return u == null ? null : new AccountAtTime(u.username(), u.accountCount(), u.firstLoginAt());
    }
  }
}
