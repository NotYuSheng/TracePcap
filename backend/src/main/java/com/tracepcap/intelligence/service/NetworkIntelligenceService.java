package com.tracepcap.intelligence.service;

import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.hostlog.entity.DnsQueryLogEntity;
import com.tracepcap.hostlog.entity.HttpEndpointLogEntity;
import com.tracepcap.hostlog.repository.DnsQueryLogRepository;
import com.tracepcap.hostlog.repository.HttpEndpointLogRepository;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.GeoOrgLookup;
import com.tracepcap.analysis.spi.GeoOrgLookup.IpPlace;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.PacketLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import com.tracepcap.analysis.spi.ServiceLogRoles;
import com.tracepcap.analysis.service.GeoIpService;
import com.tracepcap.intelligence.dto.*;
import com.tracepcap.intelligence.entity.IpOrgRuleEntity;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class NetworkIntelligenceService {

  private final ConversationLookup conversationLookup;
  private final HostClassificationLookup hostClassificationLookup;
  private final GeoOrgLookup geoOrgLookup;
  private final PacketLookup packetLookup;
  private final DnsQueryLogRepository dnsQueryLogRepository;
  private final HttpEndpointLogRepository httpEndpointLogRepository;
  private final IpOrgRuleService ipOrgRuleService;
  private final GeoIpService geoIpService;

  private static final int SAMPLE_IPS_LIMIT = 20;
  private static final int DOMINANT_PROTOCOLS_LIMIT = 3;

  @Value("${tracepcap.intelligence.max-clusters:60}")
  private int maxClusters;

  @Value("${tracepcap.intelligence.max-edges:200}")
  private int maxEdges;

  @Value("${tracepcap.dns.nxdomain-suspicious-ratio:0.5}")
  private double dnsNxdomainSuspiciousRatio;

  @Value("${tracepcap.dns.nxdomain-min-queries:20}")
  private int dnsNxdomainMinQueries;

  @Value("${tracepcap.http.client-error-suspicious-ratio:0.5}")
  private double httpClientErrorSuspiciousRatio;

  @Value("${tracepcap.http.min-requests:20}")
  private int httpMinRequests;

  // ── Public API ────────────────────────────────────────────────────────────

  public ClusterGraphResponse computeClusters(UUID fileId, String groupBy, ConversationFilterParams filterParams, List<String> networkLabels) {
    log.info("Computing {} clusters for file {}", groupBy, fileId);
    List<ConversationFacts> conversations =
        conversationLookup.conversationFacts(
            fileId, (filterParams != null && hasActiveFilters(filterParams)) ? filterParams : null);

    // Network label filter: keep only IPs that fall within any CIDR belonging to the
    // selected labels. A conversation is kept if BOTH endpoints are labelled IPs, or if
    // one endpoint is a labelled IP (to show what the segment talks to). The cluster-node
    // post-filter below then removes any cluster whose IPs are all outside the label CIDRs,
    // so only nodes containing at least one labelled IP remain in the graph.
    Set<String> labelledIps = new HashSet<>();
    List<IpOrgRuleEntity> netLabelRules = List.of();
    if (networkLabels != null && !networkLabels.isEmpty()) {
      List<IpOrgRuleEntity> allRules = ipOrgRuleService.loadRules();
      netLabelRules = allRules.stream()
          .filter(r -> networkLabels.contains(r.getLabel()))
          .collect(Collectors.toList());
      if (!netLabelRules.isEmpty()) {
        final List<IpOrgRuleEntity> rules = netLabelRules;
        Map<String, Boolean> matchCache = new HashMap<>();
        conversations = conversations.stream()
            .filter(c -> {
              boolean srcMatch = matchCache.computeIfAbsent(c.flow().srcIp(), ip -> ipOrgRuleService.matchIp(ip, rules) != null);
              boolean dstMatch = matchCache.computeIfAbsent(c.flow().dstIp(), ip -> ipOrgRuleService.matchIp(ip, rules) != null);
              return srcMatch || dstMatch;
            })
            .collect(Collectors.toList());
        // Track which IPs are actually inside a label CIDR
        for (ConversationFacts c : conversations) {
          if (Boolean.TRUE.equals(matchCache.get(c.flow().srcIp()))) labelledIps.add(c.flow().srcIp());
          if (Boolean.TRUE.equals(matchCache.get(c.flow().dstIp()))) labelledIps.add(c.flow().dstIp());
        }
      }
    }

    Set<String> allIps = new HashSet<>();
    for (ConversationFacts c : conversations) {
      allIps.add(c.flow().srcIp());
      allIps.add(c.flow().dstIp());
    }

    Map<String, IpPlace> geoByIp = new HashMap<>();
    Map<String, HostFacts> deviceByIp = new HashMap<>();
    Map<String, String> clusterLabels = new HashMap<>();

    if ("asn".equals(groupBy) || "country".equals(groupBy) || "city".equals(groupBy)) {
      // Ensure all IPs are enriched and cached (handles misses and incomplete entries).
      // lookupExternal is idempotent: it reads the cache first and only queries the MMDB for misses.
      geoIpService.lookupExternal(allIps);
      geoByIp.putAll(geoOrgLookup.placesFor(allIps));
    }
    if ("deviceType".equals(groupBy)) {
      hostClassificationLookup.hostFacts(fileId).forEach(h -> deviceByIp.put(h.ip(), h));
    }
    List<IpOrgRuleEntity> orgRules = "customOrg".equals(groupBy)
        ? ipOrgRuleService.loadRules()
        : List.of();

    // Map each IP to its cluster key
    Map<String, String> ipToCluster = new HashMap<>();
    for (String ip : allIps) {
      String key = getClusterKey(ip, groupBy, geoByIp, deviceByIp, orgRules);
      ipToCluster.put(ip, key);
      // Build label alongside so we can look it up later from any IP in the cluster
      clusterLabels.putIfAbsent(key, buildLabel(ip, key, groupBy, geoByIp, deviceByIp, orgRules));
    }

    // Aggregate cluster and edge stats
    Map<String, ClusterAcc> clusters = new LinkedHashMap<>();
    Map<String, EdgeAcc> edges = new LinkedHashMap<>();

    for (ConversationFacts conv : conversations) {
      String srcKey = ipToCluster.get(conv.flow().srcIp());
      String dstKey = ipToCluster.get(conv.flow().dstIp());
      boolean hasRisk = !conv.findings().flowRisks().isEmpty();

      ClusterAcc srcAcc = clusters.computeIfAbsent(srcKey, k -> new ClusterAcc());
      srcAcc.ips.add(conv.flow().srcIp());

      ClusterAcc dstAcc = clusters.computeIfAbsent(dstKey, k -> new ClusterAcc());
      dstAcc.ips.add(conv.flow().dstIp());

      if (srcKey.equals(dstKey)) {
        // Intra-cluster conversation — count once
        String srcIp = conv.flow().srcIp(), dstIp = conv.flow().dstIp();
        long bytes = conv.flow().totalBytes();
        srcAcc.totalBytes += bytes;
        srcAcc.totalPackets += conv.flow().packetCount();
        srcAcc.conversationCount++;
        srcAcc.ipBytes.merge(srcIp, bytes, Long::sum);
        srcAcc.ipBytes.merge(dstIp, bytes, Long::sum);
        srcAcc.ipConversations.merge(srcIp, 1L, Long::sum);
        srcAcc.ipConversations.merge(dstIp, 1L, Long::sum);
        srcAcc.ipPeers.computeIfAbsent(srcIp, k -> new HashSet<>()).add(dstIp);
        srcAcc.ipPeers.computeIfAbsent(dstIp, k -> new HashSet<>()).add(srcIp);
        if (hasRisk) {
          srcAcc.riskCount++;
          srcAcc.ipRisks.merge(srcIp, 1L, Long::sum);
          srcAcc.ipRisks.merge(dstIp, 1L, Long::sum);
          {
            for (String rt : conv.findings().flowRisks()) srcAcc.riskTypeCounts.merge(rt, 1L, Long::sum);
          }
        }
        srcAcc.protocolCounts.merge(conv.flow().protocol(), 1L, Long::sum);
      } else {
        // Inter-cluster conversation — count for both clusters
        long bytes = conv.flow().totalBytes();
        long pkts = conv.flow().packetCount();
        String proto = conv.flow().protocol();

        String srcIp = conv.flow().srcIp(), dstIp = conv.flow().dstIp();
        srcAcc.totalBytes += bytes;
        srcAcc.totalPackets += pkts;
        srcAcc.conversationCount++;
        srcAcc.ipBytes.merge(srcIp, bytes, Long::sum);
        srcAcc.ipConversations.merge(srcIp, 1L, Long::sum);
        srcAcc.ipPeers.computeIfAbsent(srcIp, k -> new HashSet<>()).add(dstIp);
        if (hasRisk) {
          srcAcc.riskCount++;
          srcAcc.ipRisks.merge(srcIp, 1L, Long::sum);
          {
            for (String rt : conv.findings().flowRisks()) srcAcc.riskTypeCounts.merge(rt, 1L, Long::sum);
          }
        }
        srcAcc.protocolCounts.merge(proto, 1L, Long::sum);

        dstAcc.totalBytes += bytes;
        dstAcc.totalPackets += pkts;
        dstAcc.conversationCount++;
        dstAcc.ipBytes.merge(dstIp, bytes, Long::sum);
        dstAcc.ipConversations.merge(dstIp, 1L, Long::sum);
        dstAcc.ipPeers.computeIfAbsent(dstIp, k -> new HashSet<>()).add(srcIp);
        if (hasRisk) {
          dstAcc.riskCount++;
          dstAcc.ipRisks.merge(dstIp, 1L, Long::sum);
          {
            for (String rt : conv.findings().flowRisks()) dstAcc.riskTypeCounts.merge(rt, 1L, Long::sum);
          }
        }
        dstAcc.protocolCounts.merge(proto, 1L, Long::sum);

        // Normalize edge key so A↔B and B↔A map to same entry
        String edgeKey = srcKey.compareTo(dstKey) < 0
            ? srcKey + "|||" + dstKey
            : dstKey + "|||" + srcKey;
        EdgeAcc ea = edges.computeIfAbsent(edgeKey, k -> new EdgeAcc(srcKey, dstKey));
        ea.totalBytes += bytes;
        ea.conversationCount++;
        ea.protocolCounts.merge(proto, 1L, Long::sum);
      }
    }

    // Build DTOs
    List<ClusterNodeDto> clusterDtos = clusters.entrySet().stream()
        .map(e -> {
          ClusterAcc acc = e.getValue();
          Comparator<String> byIpBytes = Comparator.comparingLong(
              (String ip) -> acc.ipBytes.getOrDefault(ip, 0L));
          List<String> sample = acc.ips.stream()
              .sorted(byIpBytes.reversed())
              .limit(SAMPLE_IPS_LIMIT)
              .collect(Collectors.toList());
          List<String> protocols = topKeys(acc.protocolCounts, DOMINANT_PROTOCOLS_LIMIT);
          List<String> topRiskTypes = topKeys(acc.riskTypeCounts, 3);
          Map<String, Long> ipPeerCounts = new HashMap<>();
          acc.ipPeers.forEach((ip, peers) -> ipPeerCounts.put(ip, (long) peers.size()));
          // Attach lat/lon for city clusters so the frontend can position markers.
          // Country clusters do not need backend coordinates — the frontend resolves
          // their pin positions from its bundled country-centroids.json.
          Double lat = null;
          Double lon = null;
          String geoSource = null;
          if ("city".equals(groupBy) || "country".equals(groupBy)) {
            for (String ip : acc.ips) {
              IpPlace geo = geoByIp.get(ip);
              if (geo != null && geo.geoSource() != null) {
                geoSource = geo.geoSource();
                if ("city".equals(groupBy) && geo.lat() != null && geo.lon() != null) {
                  lat = geo.lat();
                  lon = geo.lon();
                }
                break;
              }
            }
          }
          return ClusterNodeDto.builder()
              .id(e.getKey())
              .label(clusterLabels.getOrDefault(e.getKey(), e.getKey()))
              .groupType(groupBy)
              .hostCount(acc.ips.size())
              .totalBytes(acc.totalBytes)
              .totalPackets(acc.totalPackets)
              .conversationCount(acc.conversationCount)
              .riskCount(acc.riskCount)
              .dominantProtocols(protocols)
              .sampleIps(sample)
              .topRiskTypes(topRiskTypes)
              .ipBytes(acc.ipBytes)
              .ipConversations(acc.ipConversations)
              .ipRisks(acc.ipRisks)
              .ipPeers(ipPeerCounts)
              .lat(lat)
              .lon(lon)
              .geoSource(geoSource)
              .build();
        })
        .collect(Collectors.toList());

    // If a network label filter is active, remove cluster nodes that contain no labelled IPs
    if (!labelledIps.isEmpty()) {
      clusterDtos = clusterDtos.stream()
          .filter(dto -> dto.getSampleIps().stream().anyMatch(labelledIps::contains)
              || dto.getIpBytes().keySet().stream().anyMatch(labelledIps::contains))
          .collect(Collectors.toList());
    }

    // Prune to top maxClusters by traffic to keep rendering manageable
    int totalClusters = clusterDtos.size();
    if (clusterDtos.size() > maxClusters) {
      clusterDtos = clusterDtos.stream()
          .sorted(Comparator.comparingLong(ClusterNodeDto::getTotalBytes).reversed())
          .limit(maxClusters)
          .collect(Collectors.toList());
    }
    int hiddenClusters = totalClusters - clusterDtos.size();

    // Only keep edges between the surviving clusters, capped at maxEdges by traffic
    Set<String> keptIds = clusterDtos.stream().map(ClusterNodeDto::getId).collect(Collectors.toSet());
    List<ClusterEdgeDto> edgeDtos = edges.values().stream()
        .filter(ea -> keptIds.contains(ea.srcKey) && keptIds.contains(ea.dstKey))
        .sorted(Comparator.comparingLong((EdgeAcc ea) -> ea.totalBytes).reversed())
        .limit(maxEdges)
        .map(ea -> ClusterEdgeDto.builder()
            .sourceId(ea.srcKey)
            .targetId(ea.dstKey)
            .totalBytes(ea.totalBytes)
            .conversationCount(ea.conversationCount)
            .dominantProtocol(topKeys(ea.protocolCounts, 1).stream().findFirst().orElse(null))
            .build())
        .collect(Collectors.toList());

    return ClusterGraphResponse.builder()
        .groupType(groupBy)
        .clusters(clusterDtos)
        .edges(edgeDtos)
        .hiddenClusters(hiddenClusters)
        .build();
  }

  public TopHostsResponse computeTopHosts(UUID fileId, String sortBy, int limit) {
    log.info("Computing top hosts for file {} (sortBy={}, limit={})", fileId, sortBy, limit);
    List<ConversationFacts> conversations = conversationLookup.conversationFacts(fileId);

    // Aggregate per-IP stats
    Map<String, HostAcc> hostMap = new LinkedHashMap<>();
    for (ConversationFacts conv : conversations) {
      boolean hasRisk = !conv.findings().flowRisks().isEmpty();

      HostAcc srcAcc = hostMap.computeIfAbsent(conv.flow().srcIp(), k -> new HostAcc());
      srcAcc.totalBytes += conv.flow().totalBytes();
      srcAcc.packetCount += conv.flow().packetCount();
      srcAcc.conversationCount++;
      if (hasRisk) srcAcc.riskCount++;
      srcAcc.clientConversations++;
      if (conv.tls().hostname() != null) srcAcc.hostname = conv.tls().hostname();

      HostAcc dstAcc = hostMap.computeIfAbsent(conv.flow().dstIp(), k -> new HostAcc());
      dstAcc.totalBytes += conv.flow().totalBytes();
      dstAcc.packetCount += conv.flow().packetCount();
      dstAcc.conversationCount++;
      if (hasRisk) dstAcc.riskCount++;
      dstAcc.serverConversations++;
    }

    // Enrich with geo and device type
    Set<String> ips = hostMap.keySet();
    Map<String, IpPlace> geoByIp = new HashMap<>();
    geoByIp.putAll(geoOrgLookup.placesFor(ips));
    Map<String, HostFacts> deviceByIp = new HashMap<>();
    hostClassificationLookup.hostFacts(fileId).forEach(h -> deviceByIp.put(h.ip(), h));

    // Sort and limit
    Comparator<Map.Entry<String, HostAcc>> comparator = switch (sortBy) {
      case "packets" -> Comparator.comparingLong(e -> -e.getValue().packetCount);
      case "conversations" -> Comparator.comparingLong(e -> -e.getValue().conversationCount);
      case "risks" -> Comparator.comparingLong(e -> -e.getValue().riskCount);
      default -> Comparator.comparingLong(e -> -e.getValue().totalBytes); // "bytes" is default
    };

    List<HostSummaryDto> hosts = hostMap.entrySet().stream()
        .sorted(comparator)
        .limit(limit)
        .map(e -> {
          String ip = e.getKey();
          HostAcc acc = e.getValue();
          IpPlace geo = geoByIp.get(ip);
          HostFacts device = deviceByIp.get(ip);
          String role = acc.clientConversations > acc.serverConversations * 2 ? "client"
              : acc.serverConversations > acc.clientConversations * 2 ? "server"
              : "both";
          // Prefer the host's own discovered name (DHCP/mDNS/NBNS/reverse DNS) over the
          // nDPI SNI, which records the server a client connected to rather than the host itself.
          boolean useDeviceHostname = device != null && device.hostname() != null;
          String hostname = useDeviceHostname ? device.hostname() : acc.hostname;
          // Only attach a discovery-source badge when the passively-discovered name is the one shown.
          String hostnameSource = useDeviceHostname ? device.hostnameSource() : null;
          return HostSummaryDto.builder()
              .ip(ip)
              .hostname(hostname)
              .hostnameSource(hostnameSource)
              .totalBytes(acc.totalBytes)
              .packetCount(acc.packetCount)
              .conversationCount(acc.conversationCount)
              .riskCount(acc.riskCount)
              .deviceType(device != null ? device.deviceType() : null)
              .country(geo != null ? geo.countryCode() : null)
              .org(geo != null ? geo.org() : null)
              .role(role)
              .geoSource(geo != null ? geo.geoSource() : null)
              .build();
        })
        .collect(Collectors.toList());

    return TopHostsResponse.builder().hosts(hosts).build();
  }

  // ── DNS query log (#362) ────────────────────────────────────────────────────

  /**
   * Lists every host that answered DNS queries in the capture, with a per-server roll-up of
   * resolved vs. failed queries and the NXDOMAIN-based suspicious verdict. Sorted most-active first.
   */
  public List<ServiceServerSummaryDto> computeDnsServers(UUID fileId) {
    List<DnsQueryLogEntity> rows = dnsQueryLogRepository.findByFileId(fileId);
    if (rows.isEmpty()) return List.of();

    Map<String, List<DnsQueryLogEntity>> byServer =
        rows.stream().collect(Collectors.groupingBy(DnsQueryLogEntity::getServerIp));
    Map<String, HostFacts> hostByIp = new HashMap<>();
    hostClassificationLookup.hostFacts(fileId).forEach(h -> hostByIp.put(h.ip(), h));

    return byServer.entrySet().stream()
        .map(
            e -> {
              String ip = e.getKey();
              DnsCounts c = countDns(e.getValue());
              HostFacts host = hostByIp.get(ip);
              return ServiceServerSummaryDto.builder()
                  .serverIp(ip)
                  .hostname(host != null ? host.hostname() : null)
                  .role("dns")
                  .totalRequests(c.total())
                  .okCount(c.resolved)
                  .failedCount(c.failed)
                  .anomalyRatio(c.nxdomainRatio())
                  .suspicious(c.suspicious(dnsNxdomainSuspiciousRatio, dnsNxdomainMinQueries))
                  .build();
            })
        .sorted(Comparator.comparingLong(ServiceServerSummaryDto::getTotalRequests).reversed())
        .collect(Collectors.toList());
  }

  /** Full per-domain query log for a single DNS server, with summary counts and suspicious verdict. */
  public DnsQueryLogResponse computeDnsQueryLog(UUID fileId, String serverIp) {
    List<DnsQueryLogEntity> rows = dnsQueryLogRepository.findByFileIdAndServerIp(fileId, serverIp);
    DnsCounts c = countDns(rows);
    HostFacts host =
        hostClassificationLookup.hostFactsByIp(fileId, serverIp).orElse(null);

    // General DNS log ordering: most-queried domains first, then alphabetically. Unresolvable rows
    // stay visually distinct via row styling rather than being forced to the top.
    List<DnsQueryLogResponse.DnsQueryEntryDto> entries =
        rows.stream()
            .sorted(
                Comparator.comparingInt(DnsQueryLogEntity::getQueryCount)
                    .reversed()
                    .thenComparing(DnsQueryLogEntity::getQueryName))
            .map(
                r ->
                    DnsQueryLogResponse.DnsQueryEntryDto.builder()
                        .queryName(r.getQueryName())
                        .queryType(r.getQueryType())
                        .responseCode(r.getResponseCode())
                        .resolvedIps(splitResolvedIps(r.getResolvedIps()))
                        .queryCount(r.getQueryCount())
                        .resolvable(r.isResolvable())
                        .frame(r.getSampleFrame())
                        .build())
            .collect(Collectors.toList());

    return DnsQueryLogResponse.builder()
        .serverIp(serverIp)
        .hostname(host != null ? host.hostname() : null)
        .resolvedCount(c.resolved)
        .failedCount(c.failed)
        .nxdomainRatio(c.nxdomainRatio())
        .suspicious(c.suspicious(dnsNxdomainSuspiciousRatio, dnsNxdomainMinQueries))
        .entries(entries)
        .build();
  }

  /** Roll-up of a DNS server's aggregated query rows (counted as distinct queries, not packets). */
  private record DnsCounts(long resolved, long failed, long nxdomain) {
    long total() {
      return resolved + failed;
    }

    double nxdomainRatio() {
      return total() == 0 ? 0.0 : (double) nxdomain / total();
    }

    boolean suspicious(double ratioThreshold, int minQueries) {
      return total() >= minQueries && nxdomainRatio() > ratioThreshold; // strictly exceeds
    }
  }

  private DnsCounts countDns(List<DnsQueryLogEntity> rows) {
    long resolved = 0;
    long failed = 0;
    long nxdomain = 0;
    for (DnsQueryLogEntity r : rows) {
      if (r.isResolvable()) {
        resolved++;
      } else {
        failed++;
      }
      if ("NXDOMAIN".equals(r.getResponseCode())) nxdomain++;
    }
    return new DnsCounts(resolved, failed, nxdomain);
  }

  private List<String> splitResolvedIps(String joined) {
    if (joined == null || joined.isBlank()) return List.of();
    return Arrays.stream(joined.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
  }

  // ── Web / API server log (#362 follow-up) ───────────────────────────────────

  /**
   * Lists every host classified as a web/API server (roles {@code api}/{@code web} — includes
   * HTTPS-only hosts with no cleartext endpoints), with a per-server roll-up of success vs. error
   * responses and the 4xx-enumeration verdict. Sorted most-active first.
   */
  public List<ServiceServerSummaryDto> computeWebServers(UUID fileId) {
    List<HostFacts> webHosts =
        hostClassificationLookup.hostFacts(fileId).stream()
            .filter(h -> hasRole(h, ServiceLogRoles.API)
                || hasRole(h, ServiceLogRoles.WEB))
            .toList();
    if (webHosts.isEmpty()) return List.of();

    Map<String, List<HttpEndpointLogEntity>> byServer =
        httpEndpointLogRepository.findByFileId(fileId).stream()
            .collect(Collectors.groupingBy(HttpEndpointLogEntity::getServerIp));

    return webHosts.stream()
        .map(
            host -> {
              WebCounts c = countWeb(byServer.getOrDefault(host.ip(), List.of()));
              return ServiceServerSummaryDto.builder()
                  .serverIp(host.ip())
                  .hostname(host.hostname())
                  .role(hasRole(host, ServiceLogRoles.API) ? ServiceLogRoles.API : ServiceLogRoles.WEB)
                  .totalRequests(c.total())
                  .okCount(c.success)
                  .failedCount(c.clientError + c.serverError)
                  .anomalyRatio(c.clientErrorRatio())
                  .suspicious(c.suspicious(httpClientErrorSuspiciousRatio, httpMinRequests))
                  .build();
            })
        .sorted(Comparator.comparingLong(ServiceServerSummaryDto::getTotalRequests).reversed())
        .collect(Collectors.toList());
  }

  /** Full endpoint log + server detail (software, content types, TLS) for one web/API server. */
  public WebServerDetailResponse computeWebServerDetail(UUID fileId, String serverIp) {
    List<HttpEndpointLogEntity> rows =
        httpEndpointLogRepository.findByFileIdAndServerIp(fileId, serverIp);
    WebCounts c = countWeb(rows);
    HostFacts host =
        hostClassificationLookup.hostFactsByIp(fileId, serverIp).orElse(null);

    List<WebServerDetailResponse.HttpEndpointDto> endpoints =
        rows.stream()
            .sorted(
                Comparator.comparingInt(HttpEndpointLogEntity::getRequestCount)
                    .reversed()
                    .thenComparing(HttpEndpointLogEntity::getPath))
            .map(
                r ->
                    WebServerDetailResponse.HttpEndpointDto.builder()
                        .method(r.getMethod())
                        .path(r.getPath())
                        .topStatus(r.getTopStatus())
                        .requestCount(r.getRequestCount())
                        .successCount(r.getSuccessCount())
                        .clientErrorCount(r.getClientErrorCount())
                        .serverErrorCount(r.getServerErrorCount())
                        .contentType(r.getContentType())
                        .requestFrame(r.getRequestFrame())
                        .responseFrame(r.getResponseFrame())
                        .build())
            .collect(Collectors.toList());

    String serverSoftware =
        rows.stream().map(HttpEndpointLogEntity::getServerSoftware).filter(s -> s != null).findFirst().orElse(null);
    List<String> contentTypes =
        rows.stream()
            .map(HttpEndpointLogEntity::getContentType)
            .filter(ct -> ct != null)
            .distinct()
            .sorted()
            .toList();

    return WebServerDetailResponse.builder()
        .serverIp(serverIp)
        .hostname(host != null ? host.hostname() : null)
        .api(host != null && hasRole(host, ServiceLogRoles.API))
        .totalRequests(c.total())
        .successCount(c.success)
        .clientErrorCount(c.clientError)
        .serverErrorCount(c.serverError)
        .clientErrorRatio(c.clientErrorRatio())
        .suspicious(c.suspicious(httpClientErrorSuspiciousRatio, httpMinRequests))
        .serverSoftware(serverSoftware)
        .contentTypes(contentTypes)
        .tls(buildTlsInfo(fileId, serverIp))
        .endpoints(endpoints)
        .build();
  }

  /** Reconstructs TLS metadata for a server from the existing conversation enrichment; null if none. */
  private WebServerDetailResponse.TlsInfo buildTlsInfo(UUID fileId, String serverIp) {
    List<ConversationFacts> all = conversationLookup.conversationFactsForIp(fileId, serverIp);
    if (all.isEmpty()) return null;
    // The host is the TLS server when it's the connection destination (the authoritative direction).
    // If a capture stored the flow reversed (e.g. the client SYN wasn't captured) the host can appear
    // as the source, so fall back to all of its conversations rather than silently dropping the cert.
    List<ConversationFacts> serverSide =
        all.stream().filter(c -> serverIp.equals(c.flow().dstIp())).toList();
    List<ConversationFacts> convs = serverSide.isEmpty() ? all : serverSide;

    List<String> sniNames =
        convs.stream().map((java.util.function.Function<ConversationFacts,String>) f -> f.tls().hostname()).filter(h -> h != null).distinct().sorted().toList();
    ConversationFacts cert =
        convs.stream().filter(c -> c.tls().tlsSubject() != null || c.tls().tlsIssuer() != null).findFirst().orElse(null);
    String ja3s =
        convs.stream().map((java.util.function.Function<ConversationFacts,String>) f -> f.tls().ja3Server()).filter(j -> j != null).findFirst().orElse(null);

    if (cert == null && ja3s == null && sniNames.isEmpty()) return null;
    return WebServerDetailResponse.TlsInfo.builder()
        .subject(cert != null ? cert.tls().tlsSubject() : null)
        .issuer(cert != null ? cert.tls().tlsIssuer() : null)
        .ja3s(ja3s)
        .sniNames(sniNames)
        .notBefore(cert != null ? cert.tls().tlsNotBefore() : null)
        .notAfter(cert != null ? cert.tls().tlsNotAfter() : null)
        .build();
  }

  /** Roll-up of a web server's endpoint rows by status class. */
  private record WebCounts(long success, long clientError, long serverError) {
    long total() {
      return success + clientError + serverError;
    }

    double clientErrorRatio() {
      return total() == 0 ? 0.0 : (double) clientError / total();
    }

    boolean suspicious(double ratioThreshold, int minRequests) {
      return total() >= minRequests && clientErrorRatio() > ratioThreshold; // strictly exceeds
    }
  }

  private WebCounts countWeb(List<HttpEndpointLogEntity> rows) {
    long success = 0;
    long clientError = 0;
    long serverError = 0;
    for (HttpEndpointLogEntity r : rows) {
      success += r.getSuccessCount();
      clientError += r.getClientErrorCount();
      serverError += r.getServerErrorCount();
    }
    return new WebCounts(success, clientError, serverError);
  }

  /** Resolves a frame number to the conversation that contains it, so the UI can open + highlight it. */
  public PacketLocationResponse locatePacket(UUID fileId, long packetNumber) {
    return packetLookup
        .conversationIdForFrame(fileId, packetNumber)
        .map(
            conversationId ->
                PacketLocationResponse.builder()
                    .conversationId(conversationId)
                    .packetNumber(packetNumber)
                    .build())
        .orElse(null);
  }

  private boolean hasRole(HostFacts host, String role) {
    // The port splits the stored comma-joined column for us; no re-parsing here.
    return host.serviceRoles().contains(role);
  }

  // ── Filter helpers ────────────────────────────────────────────────────────

  private boolean hasActiveFilters(ConversationFilterParams p) {
    return (p.getIp() != null && !p.getIp().isBlank())
        || p.getPort() != null
        || (p.getProtocols() != null && !p.getProtocols().isEmpty())
        || (p.getL7Protocols() != null && !p.getL7Protocols().isEmpty())
        || (p.getApps() != null && !p.getApps().isEmpty())
        || (p.getCategories() != null && !p.getCategories().isEmpty())
        || Boolean.TRUE.equals(p.getHasRisks())
        || (p.getFileTypes() != null && !p.getFileTypes().isEmpty())
        || (p.getRiskTypes() != null && !p.getRiskTypes().isEmpty())
        || (p.getCustomSignatures() != null && !p.getCustomSignatures().isEmpty())
        || (p.getPayloadContains() != null && !p.getPayloadContains().isBlank())
        || (p.getDeviceTypes() != null && !p.getDeviceTypes().isEmpty())
        || (p.getCountries() != null && !p.getCountries().isEmpty());
  }

  // ── Clustering logic ──────────────────────────────────────────────────────

  private String getClusterKey(String ip, String groupBy,
      Map<String, IpPlace> geoByIp,
      Map<String, HostFacts> deviceByIp,
      List<IpOrgRuleEntity> orgRules) {
    return switch (groupBy) {
      case "asn" -> {
        IpPlace geo = geoByIp.get(ip);
        if (geo != null && geo.asn() != null && !geo.asn().isBlank()) {
          yield "asn:" + geo.asn();
        }
        yield isPrivateIp(ip) ? "cluster:internal" : "cluster:unknown";
      }
      case "country" -> {
        IpPlace geo = geoByIp.get(ip);
        if (geo != null && geo.countryCode() != null && !geo.countryCode().isBlank()) {
          yield "country:" + geo.countryCode();
        }
        yield isPrivateIp(ip) ? "cluster:internal" : "cluster:unknown";
      }
      case "city" -> {
        IpPlace geo = geoByIp.get(ip);
        if (geo != null && geo.city() != null && !geo.city().isBlank()) {
          String cc = geo.countryCode() != null ? geo.countryCode() : "XX";
          yield "city:" + cc + ":" + geo.city();
        }
        yield isPrivateIp(ip) ? "cluster:internal" : "cluster:unknown";
      }
      case "subnet24" -> "subnet24:" + subnetPrefix(ip, 3);
      case "subnet16" -> "subnet16:" + subnetPrefix(ip, 2);
      case "deviceType" -> {
        HostFacts dev = deviceByIp.get(ip);
        yield "device:" + (dev != null ? dev.deviceType() : "UNKNOWN");
      }
      case "customOrg" -> {
        String label = ipOrgRuleService.matchIp(ip, orgRules);
        if (label != null) yield "org:" + label;
        // Fallback: subnet /24
        yield "subnet24:" + subnetPrefix(ip, 3);
      }
      default -> "cluster:all";
    };
  }

  private String buildLabel(String ip, String key, String groupBy,
      Map<String, IpPlace> geoByIp,
      Map<String, HostFacts> deviceByIp,
      List<IpOrgRuleEntity> orgRules) {
    return switch (groupBy) {
      case "asn" -> {
        if (key.equals("cluster:internal")) yield "Internal Network";
        if (key.equals("cluster:unknown")) yield "Unknown (No ASN)";
        IpPlace geo = geoByIp.get(ip);
        String asn = key.substring("asn:".length());
        String org = geo != null && geo.org() != null ? geo.org() : asn;
        yield org + " (" + asn + ")";
      }
      case "country" -> {
        if (key.equals("cluster:internal")) yield "Internal Network";
        if (key.equals("cluster:unknown")) yield "Unknown Country";
        IpPlace geo = geoByIp.get(ip);
        String code = key.substring("country:".length());
        String name = geo != null && geo.country() != null ? geo.country() : code;
        yield name + " (" + code + ")";
      }
      case "city" -> {
        if (key.equals("cluster:internal")) yield "Internal Network";
        if (key.equals("cluster:unknown")) yield "Unknown Location";
        // key format: "city:<CC>:<CityName>"
        String[] parts = key.split(":", 3);
        String cityName = parts.length == 3 ? parts[2] : key;
        String cc = parts.length >= 2 ? parts[1] : "";
        IpPlace geo = geoByIp.get(ip);
        String country = (geo != null && geo.country() != null) ? geo.country() : cc;
        yield cityName + ", " + country;
      }
      case "subnet24" -> {
        String prefix = key.substring("subnet24:".length());
        yield prefix + ".x";
      }
      case "subnet16" -> {
        String prefix = key.substring("subnet16:".length());
        yield prefix + ".x.x";
      }
      case "deviceType" -> {
        String type = key.substring("device:".length());
        yield switch (type) {
          case "ROUTER" -> "Routers";
          case "SERVER" -> "Servers";
          case "MOBILE" -> "Mobile Devices";
          case "LAPTOP_DESKTOP" -> "Laptops & Desktops";
          case "IOT" -> "IoT Devices";
          default -> "Unclassified";
        };
      }
      case "customOrg" -> {
        if (key.startsWith("org:")) yield key.substring("org:".length());
        // Fallback subnet24 label
        String prefix = key.replace("subnet24:", "");
        yield prefix + ".x (untagged)";
      }
      default -> key;
    };
  }

  // ── Utilities ─────────────────────────────────────────────────────────────

  private boolean isPrivateIp(String ip) {
    if (ip == null) return false;
    return ip.startsWith("10.")
        || ip.startsWith("192.168.")
        || ip.startsWith("127.")
        || ip.equals("::1")
        || isPrivate172(ip)
        || ip.toLowerCase().startsWith("fc")
        || ip.toLowerCase().startsWith("fd");
  }

  private boolean isPrivate172(String ip) {
    if (!ip.startsWith("172.")) return false;
    try {
      int second = Integer.parseInt(ip.split("\\.")[1]);
      return second >= 16 && second <= 31;
    } catch (Exception e) {
      return false;
    }
  }

  private String subnetPrefix(String ip, int octets) {
    if (ip == null) return "unknown";
    if (ip.contains(":")) {
      // IPv6: use first N colon-separated groups
      String[] parts = ip.split(":");
      int take = Math.min(octets, parts.length);
      return String.join(":", Arrays.copyOf(parts, take));
    }
    String[] parts = ip.split("\\.");
    int take = Math.min(octets, parts.length);
    return String.join(".", Arrays.copyOf(parts, take));
  }

  private List<String> topKeys(Map<String, Long> counts, int n) {
    return counts.entrySet().stream()
        .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
        .limit(n)
        .map(Map.Entry::getKey)
        .collect(Collectors.toList());
  }
  // ── Accumulators (private inner classes) ─────────────────────────────────

  private static class ClusterAcc {
    Set<String> ips = new LinkedHashSet<>();
    long totalBytes = 0;
    long totalPackets = 0;
    long conversationCount = 0;
    long riskCount = 0;
    Map<String, Long> protocolCounts = new HashMap<>();
    Map<String, Long> riskTypeCounts = new HashMap<>();
    Map<String, Long> ipBytes = new HashMap<>();
    Map<String, Long> ipConversations = new HashMap<>();
    Map<String, Long> ipRisks = new HashMap<>();
    Map<String, Set<String>> ipPeers = new HashMap<>();
  }

  private static class EdgeAcc {
    final String srcKey;
    final String dstKey;
    long totalBytes = 0;
    long conversationCount = 0;
    Map<String, Long> protocolCounts = new HashMap<>();

    EdgeAcc(String srcKey, String dstKey) {
      this.srcKey = srcKey;
      this.dstKey = dstKey;
    }
  }

  private static class HostAcc {
    long totalBytes = 0;
    long packetCount = 0;
    long conversationCount = 0;
    long riskCount = 0;
    long clientConversations = 0;
    long serverConversations = 0;
    String hostname = null;
  }
}
