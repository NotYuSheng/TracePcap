package com.tracepcap.monitor.service;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.FindingFacet;
import com.tracepcap.analysis.spi.GeoOrgLookup;
import com.tracepcap.analysis.spi.GeoOrgLookup.IpAttribution;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import com.tracepcap.monitor.spi.LabelStalenessCheck;
import com.tracepcap.monitor.spi.SnapshotRevalidationHook;
import com.tracepcap.intelligence.entity.CustomPrivateRangeEntity;
import com.tracepcap.intelligence.entity.IpClassification;
import com.tracepcap.intelligence.service.CustomPrivateRangeService;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.ChangeType;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.EntityType;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.Severity;
import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.entity.SnapshotSubnetOverrideEntity;
import com.tracepcap.monitor.repository.NetworkChangeEventRepository;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import com.tracepcap.monitor.repository.SnapshotSubnetOverrideRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
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

  // 172.16.0.0/12 covers 172.16.x.x – 172.31.x.x (second octet 16–31)
  private static final int PRIVATE_172_MIN = 16;
  private static final int PRIVATE_172_MAX = 31;

  private final HostClassificationLookup hostClassificationLookup;
  private final ConversationLookup conversationLookup;
  private final GeoOrgLookup geoOrgLookup;
  private final NetworkChangeEventRepository changeEventRepository;
  private final CustomPrivateRangeService customPrivateRangeService;
  private final SnapshotSubnetOverrideRepository snapshotSubnetOverrideRepository;
  private final LabelStalenessCheck labelStalenessCheck;
  private final NetworkSnapshotRepository snapshotRepository;
  private final List<SnapshotRevalidationHook> revalidationHooks;
  private final SubnetOverrideCarryForwardService subnetOverrideCarryForwardService;

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
    events.addAll(detectSecurityDrift(fromFileId, toFileId, fromSnapshot, toSnapshot));
    events.addAll(detectStaleLabels(toFileId, fromSnapshot, toSnapshot));

    // Carry subnet labels forward onto this snapshot (inherited overrides), mirroring node roles.
    subnetOverrideCarryForwardService.carryForward(
        fromSnapshot != null ? fromSnapshot.getId() : null, toSnapshot.getId());

    // Feature-module baselines (subnet compositions today) re-validate against this snapshot
    // through the SnapshotRevalidationHook port — implementors depend on monitor, not vice versa.
    // Revalidation is advisory; snapshot ingestion is core. The catch enforces the port's
    // degrade-gracefully contract at the seam rather than trusting implementors' discipline.
    // Caveat: a hook that joins this transaction and throws through its own @Transactional proxy
    // has already marked the tx rollback-only — the catch keeps detection's control flow (and the
    // log readable) but cannot un-doom the commit in that case.
    for (SnapshotRevalidationHook hook : revalidationHooks) {
      try {
        hook.revalidate(toSnapshot.getNetwork().getId());
      } catch (Exception e) {
        log.error(
            "Revalidation hook {} failed for network {}: {}",
            hook.getClass().getSimpleName(),
            toSnapshot.getNetwork().getId(),
            e.getMessage(),
            e);
      }
    }

    return changeEventRepository.saveAll(events);
  }

  // ── Signal 5: Manual label staleness (#369) ─────────────────────────────────

  private List<NetworkChangeEventEntity> detectStaleLabels(
      UUID toFileId, NetworkSnapshotEntity fromSnapshot, NetworkSnapshotEntity toSnapshot) {

    UUID fromFileId = fromSnapshot != null ? fromSnapshot.getFile().getId() : null;
    List<NetworkChangeEventEntity> events = new ArrayList<>();
    for (LabelStalenessCheck.Drift drift : labelStalenessCheck.carryForwardAndValidate(fromFileId, toFileId)) {
      Map<String, Object> newValue = new HashMap<>();
      newValue.put("entityType", drift.entityType());
      newValue.put("roleLabel", orEmpty(drift.roleLabel()));
      newValue.put("changes", drift.changedFields());
      events.add(
          buildEvent(
              toSnapshot.getNetwork().getId(),
              fromSnapshot,
              toSnapshot,
              ChangeType.LABEL_STALE,
              EntityType.NODE_ROLE,
              drift.entityKey(),
              null,
              newValue,
              Severity.WARNING));
    }
    return events;
  }

  /**
   * Propagate a role change on {@code fileId} forward: for each network the file belongs to, carry
   * the label forward and re-validate every snapshot after it. Lets labelling a snapshot take effect
   * immediately across the chain, rather than only when the next snapshot is ingested (#369).
   */
  public void propagateRoleChange(UUID fileId) {
    for (NetworkSnapshotEntity snap : snapshotRepository.findByFileId(fileId)) {
      List<NetworkSnapshotEntity> ordered =
          snapshotRepository.findByNetworkIdOrderBySnapshotOrderAsc(snap.getNetwork().getId());
      int idx = -1;
      for (int i = 0; i < ordered.size(); i++) {
        if (ordered.get(i).getId().equals(snap.getId())) {
          idx = i;
          break;
        }
      }
      if (idx < 0) continue;
      for (int i = idx; i + 1 < ordered.size(); i++) {
        recomputeLabelStale(ordered.get(i), ordered.get(i + 1));
      }
    }
  }

  /** Re-run only the label-staleness signal for one transition, leaving other events untouched. */
  private void recomputeLabelStale(NetworkSnapshotEntity from, NetworkSnapshotEntity to) {
    changeEventRepository.deleteByToSnapshotIdAndChangeType(to.getId(), ChangeType.LABEL_STALE);
    changeEventRepository.saveAll(detectStaleLabels(to.getFile().getId(), from, to));
  }

  // ── Signal 1: Device MAC presence ────────────────────────────────────────────

  private List<NetworkChangeEventEntity> detectMacChanges(
      UUID fromFileId,
      UUID toFileId,
      NetworkSnapshotEntity fromSnapshot,
      NetworkSnapshotEntity toSnapshot) {

    Map<String, HostFacts> fromHosts = macMap(fromFileId);
    Map<String, HostFacts> toHosts = macMap(toFileId);

    List<NetworkChangeEventEntity> events = new ArrayList<>();

    // New MACs in toSnapshot
    for (Map.Entry<String, HostFacts> entry : toHosts.entrySet()) {
      if (!fromHosts.containsKey(entry.getKey())) {
        HostFacts h = entry.getValue();
        events.add(
            buildEvent(
                toSnapshot.getNetwork().getId(),
                fromSnapshot,
                toSnapshot,
                ChangeType.MAC_ADDED,
                EntityType.DEVICE,
                h.mac(),
                null,
                Map.of(
                    "ip", orEmpty(h.ip()),
                    "manufacturer", orEmpty(h.manufacturer()),
                    "deviceType", orEmpty(h.deviceType())),
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

    // MAC → IP change (same MAC, different IP; e.g. DHCP reassignment) — WARNING
    for (Map.Entry<String, String> entry : toMacToIp.entrySet()) {
      String mac = entry.getKey();
      String toIp = entry.getValue();
      String fromIp = fromMacToIp.get(mac);
      if (fromIp != null && !fromIp.equals(toIp)) {
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

    // IP → MAC change (same IP, different MAC; possible ARP spoofing) — CRITICAL
    // Reported independently: a device may simultaneously change its own IP (DHCP drift)
    // AND claim another IP via ARP — both events are meaningful.
    for (Map.Entry<String, String> entry : toIpToMac.entrySet()) {
      String ip = entry.getKey();
      String toMac = entry.getValue();
      String fromMac = fromIpToMac.get(ip);
      if (fromMac != null && !fromMac.equals(toMac)) {
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

    LocalityRules fromCidrs = effectiveCidrs(fromSnapshot);
    LocalityRules toCidrs = effectiveCidrs(toSnapshot);
    Set<String> fromExternalIps = externalIpsForFile(fromFileId, fromCidrs);
    Set<String> toExternalIps = externalIpsForFile(toFileId, toCidrs);

    Map<String, IpAttribution> fromGeo = geoMapFor(fromExternalIps);
    Map<String, IpAttribution> toGeo = geoMapFor(toExternalIps);

    // Build ASN key sets: "asn|org"
    Map<String, IpAttribution> fromAsns = asnMap(fromGeo);
    Map<String, IpAttribution> toAsns = asnMap(toGeo);

    List<NetworkChangeEventEntity> events = new ArrayList<>();

    // New ASNs
    for (Map.Entry<String, IpAttribution> entry : toAsns.entrySet()) {
      if (!fromAsns.containsKey(entry.getKey())) {
        IpAttribution geo = entry.getValue();
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
                    "asn", orEmpty(geo.asn()),
                    "org", orEmpty(geo.org()),
                    "country", orEmpty(geo.countryCode())),
                Severity.INFO));
      }
    }

    // Lost ASNs are not actionable on their own — gateway change covers the important case

    // Gateway heuristic: top-traffic external IP
    String fromGateway = topExternalIp(fromFileId, fromGeo, fromCidrs);
    String toGateway = topExternalIp(toFileId, toGeo, toCidrs);
    // (rules threaded through so force-public overrides beat RFC1918)
    if (fromGateway != null && toGateway != null && !fromGateway.equals(toGateway)) {
      IpAttribution fromGeoEntry = fromGeo.get(fromGateway);
      IpAttribution toGeoEntry = toGeo.get(toGateway);
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
                  "asn", fromGeoEntry != null ? orEmpty(fromGeoEntry.asn()) : "",
                  "org", fromGeoEntry != null ? orEmpty(fromGeoEntry.org()) : ""),
              Map.of(
                  "ip", toGateway,
                  "asn", toGeoEntry != null ? orEmpty(toGeoEntry.asn()) : "",
                  "org", toGeoEntry != null ? orEmpty(toGeoEntry.org()) : ""),
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

    List<ConversationFacts> fromConvs = conversationLookup.conversationFacts(fromFileId);
    List<ConversationFacts> toConvs = conversationLookup.conversationFacts(toFileId);

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

  // ── Signal 6: Security posture drift (IDS / risks / signatures / file types) ──

  /**
   * Emit change events when the security-relevant signals analysis mode computes per capture appear
   * or disappear between two snapshots. This is the differential complement to the snapshot Security
   * tab: the tab shows the absolute posture, this flags what newly appeared (or cleared).
   *
   * <p>Signals and severities:
   *
   * <ul>
   *   <li><b>Suricata IDS alerts</b> — added: CRITICAL (a fresh IDS hit is high-signal), removed: INFO.
   *   <li><b>Custom signatures</b> — added: CRITICAL, removed: INFO.
   *   <li><b>nDPI flow risks</b> — added: WARNING, removed: INFO. VPN risks are intentionally
   *       excluded here because {@code detectProtocolAppDrift} already reports them as VPN_DRIFT;
   *       double-reporting would clutter the feed.
   *   <li><b>Detected file types</b> — added: INFO only. Removals are noisy (content simply not
   *       re-transferred) and not actionable, so they are not reported.
   * </ul>
   */
  private List<NetworkChangeEventEntity> detectSecurityDrift(
      UUID fromFileId,
      UUID toFileId,
      NetworkSnapshotEntity fromSnapshot,
      NetworkSnapshotEntity toSnapshot) {

    if (fromFileId == null) return List.of();

    List<NetworkChangeEventEntity> events = new ArrayList<>();

    // Fetch distinct signal values directly from the DB rather than loading full conversation
    // entities into memory — the repository already provides purpose-built distinct queries, which
    // scale to large captures. All sets are null/blank-cleaned before reaching diffSecurity's Map.of.

    // IDS alerts (Suricata) — added CRITICAL, removed INFO
    diffSecurity(
        events, fromSnapshot, toSnapshot,
        cleanSet(conversationLookup.distinctFindings(fromFileId, FindingFacet.SURICATA_ALERT)),
        cleanSet(conversationLookup.distinctFindings(toFileId, FindingFacet.SURICATA_ALERT)),
        "ids", Severity.CRITICAL, true);

    // Custom signatures — added CRITICAL, removed INFO
    diffSecurity(
        events, fromSnapshot, toSnapshot,
        cleanSet(conversationLookup.distinctFindings(fromFileId, FindingFacet.CUSTOM_SIGNATURE)),
        cleanSet(conversationLookup.distinctFindings(toFileId, FindingFacet.CUSTOM_SIGNATURE)),
        "signature", Severity.CRITICAL, true);

    // nDPI flow risks (excluding VPN, handled by VPN_DRIFT) — added WARNING, removed INFO
    diffSecurity(
        events, fromSnapshot, toSnapshot,
        nonVpnRiskSet(conversationLookup.distinctFindings(fromFileId, FindingFacet.RISK_TYPE)),
        nonVpnRiskSet(conversationLookup.distinctFindings(toFileId, FindingFacet.RISK_TYPE)),
        "risk", Severity.WARNING, true);

    // Detected file types — added INFO only (removals not actionable)
    diffSecurity(
        events, fromSnapshot, toSnapshot,
        cleanSet(conversationLookup.distinctFindings(fromFileId, FindingFacet.FILE_TYPE)),
        cleanSet(conversationLookup.distinctFindings(toFileId, FindingFacet.FILE_TYPE)),
        "fileType", Severity.INFO, false);

    return events;
  }

  /**
   * Set-diff two security-signal sets and append ADDED (and, when {@code reportRemoved}, REMOVED)
   * events. {@code signalKind} tags the {@code newValue}/{@code oldValue} payload so the UI can
   * label it (e.g. "ids", "risk"). Added events carry {@code addedSeverity}; removed events are
   * always INFO (a cleared signal is informational, not alarming).
   */
  private void diffSecurity(
      List<NetworkChangeEventEntity> events,
      NetworkSnapshotEntity fromSnapshot,
      NetworkSnapshotEntity toSnapshot,
      Set<String> from,
      Set<String> to,
      String signalKind,
      Severity addedSeverity,
      boolean reportRemoved) {

    for (String v : to) {
      if (!from.contains(v)) {
        events.add(
            buildEvent(
                toSnapshot.getNetwork().getId(), fromSnapshot, toSnapshot,
                ChangeType.SECURITY_ALERT_ADDED, EntityType.SECURITY, v,
                null, Map.of("signalKind", signalKind, "value", v), addedSeverity));
      }
    }
    if (reportRemoved) {
      for (String v : from) {
        if (!to.contains(v)) {
          events.add(
              buildEvent(
                  toSnapshot.getNetwork().getId(), fromSnapshot, toSnapshot,
                  ChangeType.SECURITY_ALERT_REMOVED, EntityType.SECURITY, v,
                  Map.of("signalKind", signalKind, "value", v), null, Severity.INFO));
        }
      }
    }
  }

  /** nDPI flow risks excluding VPN-related ones (those are reported as VPN_DRIFT). */
  private Set<String> nonVpnRiskSet(List<String> risks) {
    if (risks == null) return Set.of();
    return risks.stream()
        .filter(r -> r != null && !r.isBlank() && !r.toUpperCase().contains("VPN"))
        .collect(Collectors.toSet());
  }

  /** Null-safe distinct non-blank set from a (possibly null) list of strings. */
  private Set<String> cleanSet(List<String> values) {
    if (values == null) return Set.of();
    return values.stream().filter(s -> s != null && !s.isBlank()).collect(Collectors.toSet());
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

  private Map<String, HostFacts> macMap(UUID fileId) {
    if (fileId == null) return Map.of();
    return hostClassificationLookup.hostFacts(fileId).stream()
        .filter(h -> h.mac() != null && !h.mac().isBlank())
        .collect(Collectors.toMap(HostFacts::mac, h -> h, (a, b) -> a));
  }

  private Map<String, String> macToIpMap(UUID fileId) {
    if (fileId == null) return Map.of();
    return hostClassificationLookup.hostFacts(fileId).stream()
        .filter(h -> h.mac() != null && !h.mac().isBlank() && h.ip() != null)
        .collect(Collectors.toMap(HostFacts::mac, HostFacts::ip, (a, b) -> a));
  }

  private Map<String, String> invertMap(Map<String, String> map) {
    Map<String, String> result = new HashMap<>();
    map.forEach((k, v) -> result.putIfAbsent(v, k));
    return result;
  }

  private Set<String> externalIpsForFile(UUID fileId, LocalityRules rules) {
    if (fileId == null) return Set.of();
    return conversationLookup.conversationFacts(fileId).stream()
        .flatMap(c -> Stream.of(c.flow().srcIp(), c.flow().dstIp()))
        .filter(ip -> ip != null && !isPrivate(ip, rules))
        .collect(Collectors.toSet());
  }

  private Map<String, IpAttribution> geoMapFor(Set<String> ips) {
    return geoOrgLookup.attributionFor(ips);
  }

  /** Builds a map of "asn|org" → the first attribution seen with that ASN. */
  private Map<String, IpAttribution> asnMap(Map<String, IpAttribution> geoMap) {
    Map<String, IpAttribution> result = new HashMap<>();
    for (IpAttribution geo : geoMap.values()) {
      if (geo.asn() != null && !geo.asn().isBlank()) {
        String key = geo.asn() + "|" + orEmpty(geo.org());
        result.putIfAbsent(key, geo);
      }
    }
    return result;
  }

  /** Returns the external IP with the highest total bytes for a file (gateway heuristic). */
  private String topExternalIp(
      UUID fileId, Map<String, IpAttribution> geoMap, LocalityRules rules) {
    if (fileId == null || geoMap.isEmpty()) return null;
    Map<String, Long> ipBytes = new HashMap<>();
    for (ConversationFacts c : conversationLookup.conversationFacts(fileId)) {
      String dst = c.flow().dstIp();
      String src = c.flow().srcIp();
      String external = null;
      if (dst != null && !isPrivate(dst, rules) && geoMap.containsKey(dst)) external = dst;
      else if (src != null && !isPrivate(src, rules) && geoMap.containsKey(src))
        external = src;
      if (external != null) {
        ipBytes.merge(external, c.flow().totalBytes(), Long::sum);
      }
    }
    return ipBytes.entrySet().stream()
        .max(Map.Entry.comparingByValue())
        .map(Map.Entry::getKey)
        .orElse(null);
  }

  private Set<String> appSet(List<ConversationFacts> convs) {
    return convs.stream()
        .map(c -> c.findings().appName())
        .filter(a -> a != null && !a.isBlank())
        .map(String::toUpperCase)
        .collect(Collectors.toSet());
  }

  private Set<String> protoSet(List<ConversationFacts> convs) {
    return convs.stream()
        .map(c -> c.findings().tsharkProtocol())
        .filter(p -> p != null && !p.isBlank())
        .map(String::toUpperCase)
        .collect(Collectors.toSet());
  }

  private Set<String> vpnSet(List<ConversationFacts> convs) {
    return convs.stream()
        .flatMap(c -> c.findings().flowRisks().stream())
        .filter(r -> r != null && r.toUpperCase().contains("VPN"))
        .collect(Collectors.toSet());
  }

  /**
   * Locality inputs for a file's classification: snapshot-scoped private CIDRs plus the global
   * classification overrides (which can force either PRIVATE or PUBLIC).
   */
  private record LocalityRules(
      List<String> privateCidrs, List<CustomPrivateRangeEntity> globalOverrides) {}

  private boolean isPrivate(String ip, LocalityRules rules) {
    if (ip == null) return true;
    // A global override wins over the RFC1918 heuristic, in either direction. This is what lets a
    // private-looking address be forced to PUBLIC (and vice versa for a public address).
    switch (customPrivateRangeService.overrideFor(ip, rules.globalOverrides())) {
      case FORCE_PRIVATE -> {
        return true;
      }
      case FORCE_PUBLIC -> {
        return false;
      }
      case NONE -> {
        // fall through to the range heuristics below
      }
    }
    for (String prefix : PRIVATE_PREFIXES) {
      if (ip.startsWith(prefix)) return true;
    }
    // 172.16.0.0/12: second octet must be 16–31
    if (ip.startsWith("172.")) {
      String[] parts = ip.split("\\.", 3);
      if (parts.length >= 2) {
        try {
          int second = Integer.parseInt(parts[1]);
          if (second >= PRIVATE_172_MIN && second <= PRIVATE_172_MAX) return true;
        } catch (NumberFormatException ignored) {
        }
      }
    }
    return customPrivateRangeService.isInCidrs(ip, rules.privateCidrs());
  }

  /**
   * Returns the locality rules for a snapshot: its own subnet overrides as private CIDRs if any are
   * defined (otherwise the global private ranges), always paired with the global classification
   * overrides so force-public rules apply regardless of snapshot scope.
   */
  private LocalityRules effectiveCidrs(NetworkSnapshotEntity snapshot) {
    List<CustomPrivateRangeEntity> global = customPrivateRangeService.loadRanges();
    if (snapshot != null) {
      List<SnapshotSubnetOverrideEntity> overrides =
          snapshotSubnetOverrideRepository.findBySnapshotId(snapshot.getId());
      if (!overrides.isEmpty()) {
        List<String> snapshotCidrs =
            overrides.stream()
                .map(SnapshotSubnetOverrideEntity::getCidr)
                .collect(Collectors.toList());
        return new LocalityRules(snapshotCidrs, global);
      }
    }
    List<String> globalPrivateCidrs =
        global.stream()
            .filter(e -> e.getClassification() == IpClassification.PRIVATE)
            .map(CustomPrivateRangeEntity::getCidr)
            .collect(Collectors.toList());
    return new LocalityRules(globalPrivateCidrs, global);
  }

  private static String orEmpty(String s) {
    return s != null ? s : "";
  }
}
