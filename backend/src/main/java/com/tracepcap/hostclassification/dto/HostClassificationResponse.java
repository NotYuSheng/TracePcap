package com.tracepcap.hostclassification.dto;

import java.util.List;
import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class HostClassificationResponse {
  String ip;
  String mac;
  String manufacturer;
  String hostname;
  String hostnameSource;
  /** Windows sign-in username observed for this host (#809); null when no domain sign-in was seen. */
  String loggedInUser;
  /** How {@code loggedInUser} was discovered: {@code kerberos_as_req} or {@code ldap_dn}; null if unset. */
  String loggedInUserSource;
  /**
   * How many distinct accounts were seen signing in (#812). {@code loggedInUser} is only set when
   * this is 1. With more, show "N accounts" and the host's login timeline instead.
   */
  int loggedInUserCount;
  Integer ttl;
  String deviceType;
  int confidence;
  /** Service roles this host was detected serving (e.g. ["dns"]); drives the node modal tabs. */
  List<String> serviceRoles;
}
