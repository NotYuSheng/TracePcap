package com.tracepcap.analysis.dto;

import java.util.List;
import lombok.Builder;
import lombok.Getter;

/** Encapsulates all filter and sort parameters for the conversations listing endpoint. */
@Getter
@Builder
public class ConversationFilterParams {

  /** Free-text match against srcIp, dstIp, or hostname (case-insensitive contains). */
  private final String ip;

  /** Exact match against srcPort or dstPort. Null = no filter. */
  private final Integer port;

  /** Restrict to conversations whose protocol is in this list. Empty = no filter. */
  private final List<String> protocols;

  /** Restrict to conversations whose appName is in this list. Empty = no filter. */
  private final List<String> apps;

  /** Restrict to conversations whose category is in this list. Empty = no filter. */
  private final List<String> categories;

  /** When true, only conversations that have at least one flow risk are returned. */
  private final Boolean hasRisks;

  /**
   * Restrict to conversations that contain at least one packet with a detected file type in this
   * list. Empty = no filter.
   */
  private final List<String> fileTypes;

  /**
   * Restrict to conversations whose flow_risks array contains at least one of the given risk type
   * strings (OR match). Empty = no filter.
   */
  private final List<String> riskTypes;

  /**
   * Field to sort by. Accepted values from frontend: {@code srcIp}, {@code dstIp},
   * {@code packets}, {@code bytes}, {@code duration}, {@code startTime}.
   * Null or blank = default DB ordering.
   */
  private final String sortBy;

  /** Sort direction: "asc" (default) or "desc". */
  private final String sortDir;
}
