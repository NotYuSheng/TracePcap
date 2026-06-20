package com.tracepcap.analysis.dto;

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
}
