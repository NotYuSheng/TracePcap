package com.tracepcap.insights.dto;

import java.util.List;
import java.util.Map;
import lombok.Builder;
import lombok.Value;

/** The adjudicated identity of one host in one capture (#512 slice 5). */
@Value
@Builder
public class HostIdentityDto {
  String ip;
  /** The one answer to "what is this host?" — a device type, or the human's label verbatim. */
  String primaryLabel;
  /** HUMAN (confirmed node-role label) or MACHINE (classification vote). */
  String basis;
  int confidence;
  /** True when machine candidates were too close to call; render the contest, not the winner. */
  boolean contested;
  /**
   * Competing candidates when contested; null otherwise. Each entry is
   * {@code {label, source, score, reasons[]}} — {@code reasons} is the human-readable "why" behind
   * that candidate's score (e.g. "listens on 80/tcp (+60)"), so the UI can explain the contest.
   */
  List<Map<String, Object>> candidates;
}
