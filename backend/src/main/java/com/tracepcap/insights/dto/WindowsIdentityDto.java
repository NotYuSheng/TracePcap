package com.tracepcap.insights.dto;

import java.util.List;
import java.util.Map;
import lombok.Builder;
import lombok.Value;

/** The adjudicated Windows identity of one host in one capture (#809). */
@Value
@Builder
public class WindowsIdentityDto {
  String ip;
  /** The one answer to "who is this?" — a username/real name, or the human's label verbatim. */
  String primaryLabel;
  /** HUMAN (override) or MACHINE (Kerberos/LDAP claim). */
  String basis;
  int confidence;
  /** True when multiple distinct usernames were claimed for this IP. */
  boolean contested;
  /**
   * Corroborating/competing candidates. Each entry is {@code {label, source, score}} — {@code
   * source} is {@code kerberos_as_req}, {@code ldap_dn}, or {@code human-override}.
   */
  List<Map<String, Object>> candidates;
}
