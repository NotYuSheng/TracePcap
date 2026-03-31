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

  /** Restrict to conversations whose tsharkProtocol is in this list. Empty = no filter. */
  private final List<String> l7Protocols;

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
   * Restrict to conversations whose custom_signatures array contains at least one of the given rule
   * name strings (OR match). Empty = no filter.
   */
  private final List<String> customSignatures;

  /**
   * Restrict to conversations that contain at least one packet whose payload includes this byte
   * pattern. Accepts ASCII strings (e.g. {@code GET /admin}) or hex sequences (e.g. {@code
   * 0x474554} or {@code 47 45 54}). Null or blank = no filter.
   */
  private final String payloadContains;

  /**
   * Restrict to conversations where srcIp OR dstIp has a host classification whose deviceType is
   * in this list (OR match). Empty = no filter.
   */
  private final List<String> deviceTypes;

  /**
   * Field to sort by. Accepted values from frontend: {@code srcIp}, {@code dstIp}, {@code packets},
   * {@code bytes}, {@code duration}, {@code startTime}. Null or blank = default DB ordering.
   */
  private final String sortBy;

  /** Sort direction: "asc" (default) or "desc". */
  private final String sortDir;
}
