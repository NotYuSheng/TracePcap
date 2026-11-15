package com.tracepcap.analysis.dto;

import com.tracepcap.analysis.spi.ConversationLookup.FacetCounts;
import java.util.Map;

/**
 * Conversations per filter value for one file, shown as counts on the filter chips. Whole-file
 * counts, independent of any active filter. {@code l7Protocols} keys are upper-cased.
 */
public record ConversationFacetCountsResponse(
    Map<String, Long> protocols,
    Map<String, Long> l7Protocols,
    Map<String, Long> apps,
    Map<String, Long> categories,
    Map<String, Long> fileTypes,
    Map<String, Long> riskTypes,
    Map<String, Long> customSignatures,
    Map<String, Long> suricataAlerts,
    Map<String, Long> countries,
    Map<String, Long> deviceTypes) {

  public static ConversationFacetCountsResponse from(FacetCounts c) {
    return new ConversationFacetCountsResponse(
        c.protocols(),
        c.l7Protocols(),
        c.apps(),
        c.categories(),
        c.fileTypes(),
        c.riskTypes(),
        c.customSignatures(),
        c.suricataAlerts(),
        c.countries(),
        c.deviceTypes());
  }
}
