package com.tracepcap.hostclassification.dto;

import java.util.List;
import lombok.Builder;
import lombok.Value;

/** Distinct source MACs observed for one IP in a file (#461); >1 ⇒ possible overlap/conflict. */
@Value
@Builder
public class IpMacObservationsResponse {
  String ip;
  List<String> macs;
}
