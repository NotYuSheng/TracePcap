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

  /** Restrict to conversations whose protocol is in this list. Empty = no filter. */
  private final List<String> protocols;

  /** Restrict to conversations whose appName is in this list. Empty = no filter. */
  private final List<String> apps;

  /** Restrict to conversations whose category is in this list. Empty = no filter. */
  private final List<String> categories;

  /** When true, only conversations that have at least one flow risk are returned. */
  private final Boolean hasRisks;

  /**
   * Entity field to sort by. Accepted values: srcIp, dstIp, packetCount, totalBytes, startTime.
   * Null or blank = default DB ordering.
   */
  private final String sortBy;

  /** Sort direction: "asc" (default) or "desc". */
  private final String sortDir;
}
