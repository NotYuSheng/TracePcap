package com.tracepcap.story.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Pre-computed analytical aggregates over the full conversation dataset for a PCAP file. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StoryAggregates {

  /** Coverage of the shown conversation sample vs. the full dataset. */
  private Coverage coverage;

  /** Top external ASNs/orgs by outbound bytes (up to 7 entries). */
  private List<AsnEntry> topExternalAsns;

  /** Per-protocol total conversation count vs. at-risk count. */
  private List<ProtocolRiskEntry> protocolRiskMatrix;

  /** Aggregate TLS certificate anomaly counts across all TLS conversations. */
  private TlsAnomalySummary tlsAnomalySummary;

  /** Unknown application percentage across all conversations (0–100). */
  /**
   * Share of conversations nDPI could not name, or {@code null} when nDPI did not complete — in
   * which case the share is unknowable rather than 100% (#501).
   */
  private Double unknownAppPct;

  /**
   * Flows exhibiting periodic beaconing behaviour (CV of inter-arrival times &lt; 0.3, ≥3 flows).
   */
  private List<BeaconCandidate> beaconCandidates;

  /** How the capture's TCP connections went (#1233); null when it couldn't be computed. */
  private ConnectionOutcomes connectionOutcomes;

  /**
   * TCP connections by outcome, and where the unanswered and refused ones were aimed: a host
   * trying many closed or silent targets is scanning, one retrying a single silent server may be
   * a dead C2 or a misconfiguration.
   */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ConnectionOutcomes {
    private long answered;
    private long noAnswer;
    private long rejected;
    /** Unanswered or refused targets, most attempts first. */
    private List<FailedTarget> topFailedTargets;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class FailedTarget {
    private String srcIp;
    private String dstIp;
    private Integer dstPort;
    private long noAnswer;
    private long rejected;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class Coverage {
    private long totalConversations;
    private long shownConversations;
    private long totalPackets;
    private long shownPackets;
    private double bytesCoveragePct;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class AsnEntry {
    private String asn;
    private String org;
    private String country;
    private long bytes;
    private double pct;
    private long flowCount;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ProtocolRiskEntry {
    private String protocol;
    private long total;
    private long atRisk;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class TlsAnomalySummary {
    private long selfSigned;
    private long expired;
    private long unknownCa;
    private long total;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class BeaconCandidate {
    private String srcIp;
    private String dstIp;
    private Integer dstPort;
    private String protocol;
    private String appName;
    private int flowCount;
    private long avgIntervalMs;
    private double cv;
  }
}
