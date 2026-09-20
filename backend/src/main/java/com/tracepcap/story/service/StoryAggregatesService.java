package com.tracepcap.story.service;

import com.tracepcap.common.net.LocalityPolicy;
import com.tracepcap.common.net.LocalityRules;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ExtractionManifest;
import com.tracepcap.analysis.spi.GeoOrgLookup;
import com.tracepcap.story.dto.StoryAggregates;
import com.tracepcap.story.dto.StoryAggregates.AsnEntry;
import com.tracepcap.story.dto.StoryAggregates.BeaconCandidate;
import com.tracepcap.story.dto.StoryAggregates.Coverage;
import com.tracepcap.story.dto.StoryAggregates.ProtocolRiskEntry;
import com.tracepcap.story.dto.StoryAggregates.TlsAnomalySummary;
import com.tracepcap.story.service.detector.BeaconAnalysis;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/** Computes pre-aggregated analytical facts over the full conversation dataset for a PCAP file. */
@Slf4j
@Service
@RequiredArgsConstructor
public class StoryAggregatesService {


  private final LocalityPolicy localityPolicy;
  private final ConversationLookup conversationLookup;
  private final ExtractionManifest extractionManifest;
  private final GeoOrgLookup geoOrgLookup;

  public StoryAggregates compute(
      UUID fileId, List<ConversationFacts> shownConversations, long totalConversations) {
    try {
      long totalPackets = conversationLookup.sumPackets(fileId);
      long totalBytes = conversationLookup.sumBytes(fileId);

      return StoryAggregates.builder()
          .coverage(
              computeCoverage(shownConversations, totalConversations, totalPackets, totalBytes))
          .topExternalAsns(computeTopAsns(fileId, totalBytes))
          .protocolRiskMatrix(computeProtocolRiskMatrix(fileId))
          .tlsAnomalySummary(computeTlsSummary(fileId))
          .unknownAppPct(computeUnknownAppPct(fileId, totalConversations))
          .beaconCandidates(computeBeaconCandidates(fileId))
          .build();
    } catch (Exception e) {
      log.error("Failed to compute story aggregates for file {}: {}", fileId, e.getMessage(), e);
      return StoryAggregates.builder()
          .coverage(
              Coverage.builder()
                  .totalConversations(totalConversations)
                  .shownConversations(shownConversations.size())
                  .build())
          .topExternalAsns(List.of())
          .protocolRiskMatrix(List.of())
          .tlsAnomalySummary(TlsAnomalySummary.builder().build())
          // Aggregation failed: the share is unknown, and 0% would be a claim we cannot make.
          .unknownAppPct(null)
          .beaconCandidates(List.of())
          .build();
    }
  }

  // ── Coverage ──────────────────────────────────────────────────────────────

  private Coverage computeCoverage(
      List<ConversationFacts> shown, long totalConversations, long totalPackets, long totalBytes) {
    long shownPackets = shown.stream().mapToLong(c -> c.flow().packetCount()).sum();
    long shownBytes = shown.stream().mapToLong(c -> c.flow().totalBytes()).sum();
    double bytesCoveragePct =
        totalBytes > 0 ? Math.round(shownBytes * 1000.0 / totalBytes) / 10.0 : 0.0;
    return Coverage.builder()
        .totalConversations(totalConversations)
        .shownConversations(shown.size())
        .totalPackets(totalPackets)
        .shownPackets(shownPackets)
        .bytesCoveragePct(bytesCoveragePct)
        .build();
  }

  // ── Top External ASNs ─────────────────────────────────────────────────────

  private List<AsnEntry> computeTopAsns(UUID fileId, long totalBytes) {
    // Fetch all conversations to get dst IPs and their byte counts
    List<ConversationFacts> all = conversationLookup.conversationFacts(fileId);

    // Group external IPs → total bytes (check both src and dst)
    Map<String, Long> ipBytes = new HashMap<>();
    Map<String, Long> ipFlows = new HashMap<>();
    // Rules resolved once for the whole capture: currentRules() loads the operator's ranges, and
    // this loop asks about every endpoint in every conversation.
    LocalityRules locality = localityPolicy.currentRules();
    Map<String, Boolean> privateCache = new HashMap<>();
    for (ConversationFacts c : all) {
      String dst = c.flow().dstIp();
      String src = c.flow().srcIp();
      // Prefer dstIp as the "remote" endpoint; fall back to srcIp if dst is private/null
      String ip = null;
      if (dst != null && !privateCache.computeIfAbsent(dst, locality::isLocal)) {
        ip = dst;
      } else if (src != null
          && !privateCache.computeIfAbsent(src, locality::isLocal)) {
        ip = src;
      }
      if (ip != null) {
        ipBytes.merge(ip, c.flow().totalBytes(), Long::sum);
        ipFlows.merge(ip, 1L, Long::sum);
      }
    }

    if (ipBytes.isEmpty()) return List.of();

    // Bulk geo lookup
    Map<String, GeoOrgLookup.IpAttribution> geoByIp = geoOrgLookup.attributionFor(ipBytes.keySet());

    // Group by (asn, org, country)
    record AsnKey(String asn, String org, String country) {}
    Map<AsnKey, Long> asnBytes = new HashMap<>();
    Map<AsnKey, Long> asnFlows = new HashMap<>();
    for (Map.Entry<String, Long> e : ipBytes.entrySet()) {
      GeoOrgLookup.IpAttribution geo = geoByIp.get(e.getKey());
      AsnKey key =
          geo != null
              ? new AsnKey(geo.asn(), geo.org(), geo.countryCode())
              : new AsnKey(null, "Unknown", null);
      asnBytes.merge(key, e.getValue(), Long::sum);
      asnFlows.merge(key, ipFlows.getOrDefault(e.getKey(), 0L), Long::sum);
    }

    return asnBytes.entrySet().stream()
        .sorted(Map.Entry.<AsnKey, Long>comparingByValue().reversed())
        .limit(7)
        .map(
            e ->
                AsnEntry.builder()
                    .asn(e.getKey().asn())
                    .org(e.getKey().org())
                    .country(e.getKey().country())
                    .bytes(e.getValue())
                    .pct(
                        totalBytes > 0
                            ? Math.round(e.getValue() * 1000.0 / totalBytes) / 10.0
                            : 0.0)
                    .flowCount(asnFlows.getOrDefault(e.getKey(), 0L))
                    .build())
        .collect(Collectors.toList());
  }

  /** Delegates to the shared predicate so all four call sites agree (#694). */


  // ── Protocol × Risk Matrix ─────────────────────────────────────────────────

  private List<ProtocolRiskEntry> computeProtocolRiskMatrix(UUID fileId) {
    return conversationLookup.protocolRiskMatrix(fileId).stream()
        .map(
            row ->
                ProtocolRiskEntry.builder()
                    .protocol(row.protocol())
                    .total(row.total())
                    .atRisk(row.atRisk())
                    .build())
        .collect(Collectors.toList());
  }

  // ── TLS Anomaly Summary ────────────────────────────────────────────────────

  private TlsAnomalySummary computeTlsSummary(UUID fileId) {
    List<ConversationFacts> tlsConvs = conversationLookup.tlsConversations(fileId);
    long selfSigned = tlsConvs.stream().filter(TlsAnomalyUtil::isSelfSigned).count();
    long expired = tlsConvs.stream().filter(TlsAnomalyUtil::isExpired).count();
    long unknownCa =
        tlsConvs.stream()
            .filter(c -> !TlsAnomalyUtil.isSelfSigned(c) && TlsAnomalyUtil.isUnknownCa(c))
            .count();
    return TlsAnomalySummary.builder()
        .selfSigned(selfSigned)
        .expired(expired)
        .unknownCa(unknownCa)
        .total(tlsConvs.size())
        .build();
  }

  // ── Unknown App % ──────────────────────────────────────────────────────────

  /**
   * Share of conversations nDPI could not name, or null when nDPI did not complete.
   *
   * <p>Gated on the manifest for the same reason {@code UnknownAppDetector} is (#501): when nDPI is
   * skipped or fails, every conversation is unidentified for tooling reasons, and a raw count says
   * "100% unknown". The detector already refuses to call that a security finding — but this number
   * goes into the LLM's prompt as full-dataset context, so leaving it ungated lets the same false
   * conclusion back in through the narrative instead of the findings list. Null means "unknowable",
   * which is the truth; the prompt renders it as such.
   *
   * <p>Files analysed before the manifest existed have no row: provenance unknown, so the historic
   * behaviour stands rather than silently blanking the figure.
   */
  private Double computeUnknownAppPct(UUID fileId, long totalConversations) {
    if (totalConversations == 0) return 0.0;
    Optional<ExtractionManifest.Run> ndpiRun =
        extractionManifest.runFor(fileId, ExtractionManifest.NDPI);
    if (ndpiRun.isPresent() && ndpiRun.get().status() != ExtractionManifest.Status.COMPLETED) {
      return null;
    }
    long unknown = conversationLookup.unidentifiedAppCount(fileId);
    return Math.round(unknown * 1000.0 / totalConversations) / 10.0;
  }

  // ── Beacon Candidates ──────────────────────────────────────────────────────

  /**
   * The Traffic-intelligence panel's beacon candidates (and the prompt's). Delegates to
   * {@link BeaconAnalysis}, the same analysis the beacon detector uses (#823): this used to be a
   * second copy of the algorithm with the same flaws, so a domain controller's NetBIOS keepalive was
   * listed here as a beacon candidate — once per protocol view — even after the detector stopped
   * reporting it. External candidates come first, then the most regular; top 5.
   */
  private List<BeaconCandidate> computeBeaconCandidates(UUID fileId) {
    return BeaconAnalysis.analyse(conversationLookup.conversationFacts(fileId)).stream()
        .limit(5)
        .map(
            c ->
                BeaconCandidate.builder()
                    .srcIp(c.client())
                    .dstIp(c.server())
                    .dstPort(c.serverPort())
                    .protocol(String.join("/", c.protocols().stream().filter(p -> !p.isEmpty()).toList()))
                    .appName(c.appName())
                    .flowCount(c.flows())
                    .avgIntervalMs(Math.round(c.meanMs()))
                    .cv(Math.round(c.cv() * 1000.0) / 1000.0)
                    .build())
        .collect(Collectors.toList());
  }
}
