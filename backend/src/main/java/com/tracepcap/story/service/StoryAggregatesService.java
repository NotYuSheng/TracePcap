package com.tracepcap.story.service;

import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import com.tracepcap.story.dto.StoryAggregates;
import com.tracepcap.story.dto.StoryAggregates.AsnEntry;
import com.tracepcap.story.dto.StoryAggregates.BeaconCandidate;
import com.tracepcap.story.dto.StoryAggregates.Coverage;
import com.tracepcap.story.dto.StoryAggregates.ProtocolRiskEntry;
import com.tracepcap.story.dto.StoryAggregates.TlsAnomalySummary;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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

  private static final Set<String> PRIVATE_PREFIXES =
      Set.of("10.", "127.", "169.254.", "::1", "fc", "fd", "fe80");

  private final ConversationRepository conversationRepository;
  private final IpGeoInfoRepository ipGeoInfoRepository;

  public StoryAggregates compute(
      UUID fileId, List<ConversationEntity> shownConversations, long totalConversations) {
    try {
      long totalPackets = conversationRepository.sumPacketsByFileId(fileId);
      long totalBytes = conversationRepository.sumTotalBytesByFileId(fileId);

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
          .unknownAppPct(0)
          .beaconCandidates(List.of())
          .build();
    }
  }

  // ── Coverage ──────────────────────────────────────────────────────────────

  private Coverage computeCoverage(
      List<ConversationEntity> shown, long totalConversations, long totalPackets, long totalBytes) {
    long shownPackets = shown.stream().mapToLong(ConversationEntity::getPacketCount).sum();
    long shownBytes = shown.stream().mapToLong(ConversationEntity::getTotalBytes).sum();
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
    List<ConversationEntity> all = conversationRepository.findByFileId(fileId);

    // Group external IPs → total bytes (check both src and dst)
    Map<String, Long> ipBytes = new HashMap<>();
    Map<String, Long> ipFlows = new HashMap<>();
    Map<String, Boolean> privateCache = new HashMap<>();
    for (ConversationEntity c : all) {
      String dst = c.getDstIp();
      String src = c.getSrcIp();
      // Prefer dstIp as the "remote" endpoint; fall back to srcIp if dst is private/null
      String ip = null;
      if (dst != null && !privateCache.computeIfAbsent(dst, StoryAggregatesService::isPrivate)) {
        ip = dst;
      } else if (src != null
          && !privateCache.computeIfAbsent(src, StoryAggregatesService::isPrivate)) {
        ip = src;
      }
      if (ip != null) {
        ipBytes.merge(ip, c.getTotalBytes(), Long::sum);
        ipFlows.merge(ip, 1L, Long::sum);
      }
    }

    if (ipBytes.isEmpty()) return List.of();

    // Bulk geo lookup
    Map<String, IpGeoInfoEntity> geoByIp =
        ipGeoInfoRepository.findAllByIpIn(ipBytes.keySet()).stream()
            .collect(Collectors.toMap(IpGeoInfoEntity::getIp, g -> g, (a, b) -> a));

    // Group by (asn, org, country)
    record AsnKey(String asn, String org, String country) {}
    Map<AsnKey, Long> asnBytes = new HashMap<>();
    Map<AsnKey, Long> asnFlows = new HashMap<>();
    for (Map.Entry<String, Long> e : ipBytes.entrySet()) {
      IpGeoInfoEntity geo = geoByIp.get(e.getKey());
      AsnKey key =
          geo != null
              ? new AsnKey(geo.getAsn(), geo.getOrg(), geo.getCountryCode())
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

  private static boolean isPrivate(String ip) {
    for (String prefix : PRIVATE_PREFIXES) {
      if (ip.startsWith(prefix)) return true;
    }
    // 172.16.0.0/12
    if (ip.startsWith("172.")) {
      String[] parts = ip.split("\\.");
      if (parts.length >= 2) {
        try {
          int second = Integer.parseInt(parts[1]);
          if (second >= 16 && second <= 31) return true;
        } catch (NumberFormatException ignored) {
        }
      }
    }
    // 192.168.x.x
    if (ip.startsWith("192.168.")) return true;
    return false;
  }

  // ── Protocol × Risk Matrix ─────────────────────────────────────────────────

  private List<ProtocolRiskEntry> computeProtocolRiskMatrix(UUID fileId) {
    return conversationRepository.findProtocolRiskMatrixByFileId(fileId).stream()
        .map(
            row ->
                ProtocolRiskEntry.builder()
                    .protocol(String.valueOf(row[0]))
                    .total(((Number) row[1]).longValue())
                    .atRisk(((Number) row[2]).longValue())
                    .build())
        .collect(Collectors.toList());
  }

  // ── TLS Anomaly Summary ────────────────────────────────────────────────────

  private TlsAnomalySummary computeTlsSummary(UUID fileId) {
    List<ConversationEntity> tlsConvs = conversationRepository.findTlsConversationsByFileId(fileId);
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

  private double computeUnknownAppPct(UUID fileId, long totalConversations) {
    if (totalConversations == 0) return 0.0;
    long unknown = conversationRepository.countUnknownAppByFileId(fileId);
    return Math.round(unknown * 1000.0 / totalConversations) / 10.0;
  }

  // ── Beacon Candidates ──────────────────────────────────────────────────────

  private List<BeaconCandidate> computeBeaconCandidates(UUID fileId) {
    List<Object[]> rows = conversationRepository.findFlowsForBeaconDetection(fileId);

    // Group by (srcIp, dstIp, dstPort, protocol)
    record FlowKey(String src, String dst, String port, String proto, String app) {}
    Map<FlowKey, List<LocalDateTime>> groups = new HashMap<>();
    for (Object[] row : rows) {
      String src = String.valueOf(row[0]);
      String dst = row[1] != null ? String.valueOf(row[1]) : "";
      String port = row[2] != null ? String.valueOf(row[2]) : "";
      String proto = String.valueOf(row[3]);
      String app = row[4] != null ? String.valueOf(row[4]) : null;
      FlowKey key = new FlowKey(src, dst, port, proto, app);
      LocalDateTime ts =
          row[5] instanceof java.sql.Timestamp t ? t.toLocalDateTime() : (LocalDateTime) row[5];
      groups.computeIfAbsent(key, k -> new ArrayList<>()).add(ts);
    }

    List<BeaconCandidate> candidates = new ArrayList<>();
    for (Map.Entry<FlowKey, List<LocalDateTime>> e : groups.entrySet()) {
      List<LocalDateTime> times = e.getValue();
      if (times.size() < 3) continue;

      // Compute inter-arrival intervals in milliseconds
      List<Long> intervals = new ArrayList<>();
      for (int i = 1; i < times.size(); i++) {
        long ms = java.time.Duration.between(times.get(i - 1), times.get(i)).toMillis();
        if (ms >= 0) intervals.add(ms);
      }
      if (intervals.isEmpty()) continue;

      double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0);
      if (mean < 1000) continue; // ignore sub-second intervals (not beaconing)

      double variance =
          intervals.stream().mapToDouble(v -> Math.pow(v - mean, 2)).average().orElse(0);
      double stddev = Math.sqrt(variance);
      double cv = stddev / mean;

      if (cv < 0.3) {
        FlowKey k = e.getKey();
        candidates.add(
            BeaconCandidate.builder()
                .srcIp(k.src())
                .dstIp(k.dst().isEmpty() ? null : k.dst())
                .dstPort(k.port().isEmpty() ? null : parsePort(k.port()))
                .protocol(k.proto())
                .appName(k.app())
                .flowCount(times.size())
                .avgIntervalMs(Math.round(mean))
                .cv(Math.round(cv * 1000.0) / 1000.0)
                .build());
      }
    }

    // Sort by CV ascending (lowest jitter = most suspicious), return top 5
    candidates.sort((a, b) -> Double.compare(a.getCv(), b.getCv()));
    return candidates.stream().limit(5).collect(Collectors.toList());
  }

  private static Integer parsePort(String s) {
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException e) {
      return null;
    }
  }
}
