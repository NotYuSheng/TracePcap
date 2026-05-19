package com.tracepcap.monitor.service;

import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.ChangeType;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.EntityType;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.Severity;
import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.repository.NetworkChangeEventRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Compares two network snapshots and emits NetworkChangeEventEntity records for each detected
 * change. Handles all four signal types: device MAC presence, IP↔MAC binding drift, ISP/ASN
 * changes, and VPN/protocol/application drift.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class ChangeDetectionService {

  private static final Set<String> PRIVATE_PREFIXES =
      Set.of("10.", "127.", "169.254.", "192.168.", "::1", "fc", "fd", "fe80");

  private final HostClassificationRepository hostClassificationRepository;
  private final ConversationRepository conversationRepository;
  private final IpGeoInfoRepository ipGeoInfoRepository;
  private final NetworkChangeEventRepository changeEventRepository;

  /**
   * Compare two consecutive snapshots and persist NetworkChangeEventEntity records. fromSnapshot
   * may be null when the first snapshot is compared against a manual baseline with no prior PCAP.
   */
  public List<NetworkChangeEventEntity> detectChanges(
      NetworkSnapshotEntity fromSnapshot, NetworkSnapshotEntity toSnapshot) {

    UUID fromFileId = fromSnapshot != null ? fromSnapshot.getFile().getId() : null;
    UUID toFileId = toSnapshot.getFile().getId();

    List<NetworkChangeEventEntity> events = new ArrayList<>();
    events.addAll(detectMacChanges(fromFileId, toFileId, fromSnapshot, toSnapshot));
    events.addAll(detectIpMacDrift(fromFileId, toFileId, fromSnapshot, toSnapshot));
    events.addAll(detectIspAsnChanges(fromFileId, toFileId, fromSnapshot, toSnapshot));
    events.addAll(detectProtocolAppDrift(fromFileId, toFileId, fromSnapshot, toSnapshot));

    return changeEventRepository.saveAll(events);
  }

  // ── Signal 1: Device MAC presence ────────────────────────────────────────────

  private List<NetworkChangeEventEntity> detectMacChanges(
      UUID fromFileId,
      UUID toFileId,
      NetworkSnapshotEntity fromSnapshot,
      NetworkSnapshotEntity toSnapshot) {

    Map<String, HostClassificationEntity> fromHosts = macMap(fromFileId);
    Map<String, HostClassificationEntity> toHosts = macMap(toFileId);

    List<NetworkChangeEventEntity> events = new ArrayList<>();

    // New MACs in toSnapshot
    for (Map.Entry<String, HostClassificationEntity> entry : toHosts.entrySet()) {
      if (!fromHosts.containsKey(entry.getKey())) {
        HostClassificationEntity h = entry.getValue();
        events.add(
            buildEvent(
                toSnapshot.getNetwork().getId(),
                fromSnapshot,
                toSnapshot,
                ChangeType.MAC_ADDED,
                EntityType.DEVICE,
                h.getMac(),
                null,
                Map.of(
                    "ip", orEmpty(h.getIp()),
                    "manufacturer", orEmpty(h.getManufacturer()),
                    "deviceType", orEmpty(h.getDeviceType())),
                Severity.WARNING));
      }
    }

    // MACs gone from toSnapshot are surfaced as absent entities in the UI — no event needed

    return events;
  }

  // ── Signal 2: IP ↔ MAC binding drift ────────────────────────────────────────

  private List<NetworkChangeEventEntity> detectIpMacDrift(
      UUID fromFileId,
      UUID toFileId,
      NetworkSnapshotEntity fromSnapshot,
      NetworkSnapshotEntity toSnapshot) {

    if (fromFileId == null) return List.of();

    Map<String, String> fromMacToIp = macToIpMap(fromFileId);
    Map<String, String> toMacToIp = macToIpMap(toFileId);
    Map<String, String> fromIpToMac = invertMap(fromMacToIp);
    Map<String, String> toIpToMac = invertMap(toMacToIp);

    List<NetworkChangeEventEntity> events = new ArrayList<>();
    Set<String> emittedMacs = new HashSet<>();

    // MAC → IP change (same MAC, different IP; e.g. DHCP reassignment)
    for (Map.Entry<String, String> entry : toMacToIp.entrySet()) {
      String mac = entry.getKey();
      String toIp = entry.getValue();
      String fromIp = fromMacToIp.get(mac);
      if (fromIp != null && !fromIp.equals(toIp)) {
        emittedMacs.add(mac);
        events.add(
            buildEvent(
                toSnapshot.getNetwork().getId(),
                fromSnapshot,
                toSnapshot,
                ChangeType.IP_MAC_DRIFT,
                EntityType.IP_MAC_BINDING,
                mac,
                Map.of("mac", mac, "ip", fromIp),
                Map.of("mac", mac, "ip", toIp),
                Severity.WARNING));
      }
    }

    // IP → MAC change (same IP, different MAC; stronger signal — possible ARP spoofing)
    for (Map.Entry<String, String> entry : toIpToMac.entrySet()) {
      String ip = entry.getKey();
      String toMac = entry.getValue();
      String fromMac = fromIpToMac.get(ip);
      if (fromMac != null && !fromMac.equals(toMac) && !emittedMacs.contains(toMac)) {
        events.add(
            buildEvent(
                toSnapshot.getNetwork().getId(),
                fromSnapshot,
                toSnapshot,
                ChangeType.IP_MAC_DRIFT,
                EntityType.IP_MAC_BINDING,
                ip,
                Map.of("ip", ip, "mac", fromMac),
                Map.of("ip", ip, "mac", toMac),
                Severity.CRITICAL));
      }
    }

    return events;
  }

  // ── Signal 3: ISP / ASN / Gateway change ────────────────────────────────────

  private List<NetworkChangeEventEntity> detectIspAsnChanges(
      UUID fromFileId,
      UUID toFileId,
      NetworkSnapshotEntity fromSnapshot,
      NetworkSnapshotEntity toSnapshot) {

    if (fromFileId == null) return List.of();

    Set<String> fromExternalIps = externalIpsForFile(fromFileId);
    Set<String> toExternalIps = externalIpsForFile(toFileId);

    Map<String, IpGeoInfoEntity> fromGeo = geoMapFor(fromExternalIps);
    Map<String, IpGeoInfoEntity> toGeo = geoMapFor(toExternalIps);

    // Build ASN key sets: "asn|org"
    Map<String, IpGeoInfoEntity> fromAsns = asnMap(fromGeo);
    Map<String, IpGeoInfoEntity> toAsns = asnMap(toGeo);

    List<NetworkChangeEventEntity> events = new ArrayList<>();

    // New ASNs
    for (Map.Entry<String, IpGeoInfoEntity> entry : toAsns.entrySet()) {
      if (!fromAsns.containsKey(entry.getKey())) {
        IpGeoInfoEntity geo = entry.getValue();
        events.add(
            buildEvent(
                toSnapshot.getNetwork().getId(),
                fromSnapshot,
                toSnapshot,
                ChangeType.ASN_CHANGE,
                EntityType.ISP,
                entry.getKey(),
                null,
                Map.of(
                    "asn", orEmpty(geo.getAsn()),
                    "org", orEmpty(geo.getOrg()),
                    "country", orEmpty(geo.getCountryCode())),
                Severity.INFO));
      }
    }

    // Lost ASNs are not actionable on their own — gateway change covers the important case

    // Gateway heuristic: top-traffic external IP
    String fromGateway = topExternalIp(fromFileId, fromGeo);
    String toGateway = topExternalIp(toFileId, toGeo);
    if (fromGateway != null && toGateway != null && !fromGateway.equals(toGateway)) {
      IpGeoInfoEntity fromGeoEntry = fromGeo.get(fromGateway);
      IpGeoInfoEntity toGeoEntry = toGeo.get(toGateway);
      events.add(
          buildEvent(
              toSnapshot.getNetwork().getId(),
              fromSnapshot,
              toSnapshot,
              ChangeType.GATEWAY_CHANGE,
              EntityType.ISP,
              "gateway",
              Map.of(
                  "ip", fromGateway,
                  "asn", fromGeoEntry != null ? orEmpty(fromGeoEntry.getAsn()) : "",
                  "org", fromGeoEntry != null ? orEmpty(fromGeoEntry.getOrg()) : ""),
              Map.of(
                  "ip", toGateway,
                  "asn", toGeoEntry != null ? orEmpty(toGeoEntry.getAsn()) : "",
                  "org", toGeoEntry != null ? orEmpty(toGeoEntry.getOrg()) : ""),
              Severity.CRITICAL));
    }

    return events;
  }

  // ── Signal 4: VPN / Protocol / Application drift ────────────────────────────

  private List<NetworkChangeEventEntity> detectProtocolAppDrift(
      UUID fromFileId,
      UUID toFileId,
      NetworkSnapshotEntity fromSnapshot,
      NetworkSnapshotEntity toSnapshot) {

    if (fromFileId == null) return List.of();

    List<ConversationEntity> fromConvs = conversationRepository.findByFileId(fromFileId);
    List<ConversationEntity> toConvs = conversationRepository.findByFileId(toFileId);

    Set<String> fromApps = appSet(fromConvs);
    Set<String> toApps = appSet(toConvs);
    Set<String> fromProtos = protoSet(fromConvs);
    Set<String> toProtos = protoSet(toConvs);
    Set<String> fromVpn = vpnSet(fromConvs);
    Set<String> toVpn = vpnSet(toConvs);

    List<NetworkChangeEventEntity> events = new ArrayList<>();

    // App drift
    for (String app : toApps) {
      if (!fromApps.contains(app)) {
        boolean vpnRelated = app.toUpperCase().contains("VPN");
        events.add(
            buildEvent(
                toSnapshot.getNetwork().getId(),
                fromSnapshot,
                toSnapshot,
                ChangeType.APP_ADDED,
                EntityType.APP,
                app,
                null,
                Map.of("app", app),
                vpnRelated ? Severity.WARNING : Severity.INFO));
      }
    }
    // Removed apps are surfaced as absent entities in the UI — no event needed

    // Protocol drift
    for (String proto : toProtos) {
      if (!fromProtos.contains(proto)) {
        events.add(
            buildEvent(
                toSnapshot.getNetwork().getId(),
                fromSnapshot,
                toSnapshot,
                ChangeType.PROTOCOL_ADDED,
                EntityType.PROTOCOL,
                proto,
                null,
                Map.of("protocol", proto),
                Severity.INFO));
      }
    }
    // Removed protocols are surfaced as absent entities in the UI — no event needed

    // VPN fingerprint drift
    for (String risk : toVpn) {
      if (!fromVpn.contains(risk)) {
        events.add(
            buildEvent(
                toSnapshot.getNetwork().getId(),
                fromSnapshot,
                toSnapshot,
                ChangeType.VPN_DRIFT,
                EntityType.APP,
                risk,
                null,
                Map.of("riskType", risk),
                Severity.CRITICAL));
      }
    }
    // VPN fingerprint gone is a meaningful signal — someone stopped using a VPN
    for (String risk : fromVpn) {
      if (!toVpn.contains(risk)) {
        events.add(
            buildEvent(
                toSnapshot.getNetwork().getId(),
                fromSnapshot,
                toSnapshot,
                ChangeType.VPN_DRIFT,
                EntityType.APP,
                risk,
                Map.of("riskType", risk),
                null,
                Severity.WARNING));
      }
    }

    return events;
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  private NetworkChangeEventEntity buildEvent(
      UUID networkId,
      NetworkSnapshotEntity fromSnapshot,
      NetworkSnapshotEntity toSnapshot,
      ChangeType changeType,
      EntityType entityType,
      String entityKey,
      Map<String, Object> oldValue,
      Map<String, Object> newValue,
      Severity severity) {

    return NetworkChangeEventEntity.builder()
        .network(toSnapshot.getNetwork())
        .fromSnapshot(fromSnapshot)
        .toSnapshot(toSnapshot)
        .changeType(changeType)
        .entityType(entityType)
        .entityKey(entityKey)
        .oldValue(oldValue)
        .newValue(newValue)
        .severity(severity)
        .detectedAt(LocalDateTime.now())
        .build();
  }

  private Map<String, HostClassificationEntity> macMap(UUID fileId) {
    if (fileId == null) return Map.of();
    return hostClassificationRepository.findByFileId(fileId).stream()
        .filter(h -> h.getMac() != null && !h.getMac().isBlank())
        .collect(Collectors.toMap(HostClassificationEntity::getMac, h -> h, (a, b) -> a));
  }

  private Map<String, String> macToIpMap(UUID fileId) {
    if (fileId == null) return Map.of();
    return hostClassificationRepository.findByFileId(fileId).stream()
        .filter(h -> h.getMac() != null && !h.getMac().isBlank() && h.getIp() != null)
        .collect(Collectors.toMap(HostClassificationEntity::getMac, HostClassificationEntity::getIp,
            (a, b) -> a));
  }

  private Map<String, String> invertMap(Map<String, String> map) {
    Map<String, String> result = new HashMap<>();
    map.forEach((k, v) -> result.putIfAbsent(v, k));
    return result;
  }

  private Set<String> externalIpsForFile(UUID fileId) {
    if (fileId == null) return Set.of();
    return conversationRepository.findByFileId(fileId).stream()
        .flatMap(c -> Stream.of(c.getSrcIp(), c.getDstIp()))
        .filter(ip -> ip != null && !isPrivate(ip))
        .collect(Collectors.toSet());
  }

  private Map<String, IpGeoInfoEntity> geoMapFor(Set<String> ips) {
    if (ips.isEmpty()) return Map.of();
    return ipGeoInfoRepository.findAllByIpIn(ips).stream()
        .collect(Collectors.toMap(IpGeoInfoEntity::getIp, g -> g, (a, b) -> a));
  }

  /** Builds a map of "asn|org" → first IpGeoInfoEntity with that ASN. */
  private Map<String, IpGeoInfoEntity> asnMap(Map<String, IpGeoInfoEntity> geoMap) {
    Map<String, IpGeoInfoEntity> result = new HashMap<>();
    for (IpGeoInfoEntity geo : geoMap.values()) {
      if (geo.getAsn() != null && !geo.getAsn().isBlank()) {
        String key = geo.getAsn() + "|" + orEmpty(geo.getOrg());
        result.putIfAbsent(key, geo);
      }
    }
    return result;
  }

  /** Returns the external IP with the highest total bytes for a file (gateway heuristic). */
  private String topExternalIp(UUID fileId, Map<String, IpGeoInfoEntity> geoMap) {
    if (fileId == null || geoMap.isEmpty()) return null;
    Map<String, Long> ipBytes = new HashMap<>();
    for (ConversationEntity c : conversationRepository.findByFileId(fileId)) {
      String dst = c.getDstIp();
      String src = c.getSrcIp();
      String external = null;
      if (dst != null && !isPrivate(dst) && geoMap.containsKey(dst)) external = dst;
      else if (src != null && !isPrivate(src) && geoMap.containsKey(src)) external = src;
      if (external != null) {
        ipBytes.merge(external, c.getTotalBytes() != null ? c.getTotalBytes() : 0L, Long::sum);
      }
    }
    return ipBytes.entrySet().stream()
        .max(Map.Entry.comparingByValue())
        .map(Map.Entry::getKey)
        .orElse(null);
  }

  private Set<String> appSet(List<ConversationEntity> convs) {
    return convs.stream()
        .map(ConversationEntity::getAppName)
        .filter(a -> a != null && !a.isBlank())
        .map(String::toUpperCase)
        .collect(Collectors.toSet());
  }

  private Set<String> protoSet(List<ConversationEntity> convs) {
    return convs.stream()
        .map(ConversationEntity::getTsharkProtocol)
        .filter(p -> p != null && !p.isBlank())
        .map(String::toUpperCase)
        .collect(Collectors.toSet());
  }

  private Set<String> vpnSet(List<ConversationEntity> convs) {
    return convs.stream()
        .filter(c -> c.getFlowRisks() != null)
        .flatMap(c -> Arrays.stream(c.getFlowRisks()))
        .filter(r -> r != null && r.toUpperCase().contains("VPN"))
        .collect(Collectors.toSet());
  }

  private static boolean isPrivate(String ip) {
    if (ip == null) return true;
    for (String prefix : PRIVATE_PREFIXES) {
      if (ip.startsWith(prefix)) return true;
    }
    return false;
  }

  private static String orEmpty(String s) {
    return s != null ? s : "";
  }
}
