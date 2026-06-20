package com.tracepcap.analysis.dto;

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
  Integer ttl;
  String deviceType;
  int confidence;
  /** Service roles this host was detected serving (e.g. ["dns"]); drives the node modal tabs. */
  List<String> serviceRoles;
}
