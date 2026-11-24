package com.tracepcap.analysis.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * How complete a capture is, and how fully it was inspected (#1268), so a missing answer can be
 * told apart from a clean one.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CaptureQualityResponse {
  /** {@code complete}, or {@code notes} when any {@link #notes} apply. */
  private String verdict;
  /** Plain-language notes, most consequential first; empty when nothing stood out. */
  private List<Note> notes;

  private long tcpConversations;
  /** TCP conversations whose opening handshake isn't in the capture: already open when it began. */
  private long tcpWithoutHandshake;
  /** Suricata's counters for the run; null when Suricata didn't run on this capture. */
  private Long packets;
  private Long invalidPackets;
  private Long tcpSessions;
  private Long reassemblyGaps;
  private Long streamDepthReached;
  private Long memcapDrops;

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class Note {
    /** Stable key: midstream, gaps, invalid, memcap, depth. */
    private String kind;
    /** {@code warning} when answers may be missing; {@code info} otherwise. */
    private String level;
    private String text;
  }
}
