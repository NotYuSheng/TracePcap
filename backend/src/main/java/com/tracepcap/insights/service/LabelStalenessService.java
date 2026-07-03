package com.tracepcap.insights.service;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import com.tracepcap.insights.dto.LabelDrift;
import com.tracepcap.insights.entity.NodeRoleEntity;
import com.tracepcap.insights.repository.NodeRoleRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Per-file node-role property + staleness logic (#369). Roles live per file (a monitor snapshot is
 * a file). When a new snapshot is added, each confirmed classification on the previous snapshot is
 * carried forward and validated against the new pcap's observed properties; drift on MAC, dominant
 * protocols, or external orgs flags the carried label stale.
 *
 * <p>Lives in the insights package and returns plain {@link LabelDrift} descriptors so the monitor
 * change-detection flow can raise events without this service depending on monitor types.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LabelStalenessService {

  public static final String ORIGIN_CARRIED_FORWARD = "CARRIED_FORWARD";

  private final NodeRoleRepository nodeRoleRepository;
  private final HostClassificationRepository hostClassificationRepository;
  private final IpGeoInfoRepository ipGeoInfoRepository;
  private final JdbcTemplate jdbc;

  /**
   * Carries each confirmed classification on {@code prevFileId} forward onto {@code newFileId} and
   * validates it against the new pcap. Carried rows (origin {@code CARRIED_FORWARD}) for the new
   * file are regenerated each call; entities the analyst has labelled directly on the new file
   * (origin {@code MANUAL}/{@code AI}) are left untouched and take precedence. Returns a descriptor
   * for each carried label that drifted from its baseline.
   */
  @Transactional
  public List<LabelDrift> carryForwardAndValidate(UUID prevFileId, UUID newFileId) {
    // Always clear stale carried rows so a reorder/re-add regenerates cleanly.
    nodeRoleRepository.deleteByFileIdAndOrigin(newFileId, ORIGIN_CARRIED_FORWARD);
    if (prevFileId == null || newFileId == null) return List.of();

    List<NodeRoleEntity> confirmed =
        nodeRoleRepository.findByFileIdAndConfirmedByHumanTrue(prevFileId);
    if (confirmed.isEmpty()) return List.of();

    // Entities already labelled directly on the new file — don't overwrite them.
    Set<String> ownKeys =
        nodeRoleRepository.findByFileId(newFileId).stream()
            .filter(r -> !ORIGIN_CARRIED_FORWARD.equals(r.getOrigin()))
            .map(r -> r.getEntityType() + "|" + r.getEntityKey())
            .collect(Collectors.toSet());

    // Pre-filter to entities that actually appear in the new file.
    Set<String> activeIps = new HashSet<>();
    Set<String> activeMacsLower = new HashSet<>();
    for (HostClassificationEntity h : hostClassificationRepository.findByFileId(newFileId)) {
      if (h.getIp() != null) activeIps.add(h.getIp());
      if (h.getMac() != null) activeMacsLower.add(h.getMac().toLowerCase());
    }

    List<LabelDrift> drifts = new ArrayList<>();
    for (NodeRoleEntity prev : confirmed) {
      if (ownKeys.contains(prev.getEntityType() + "|" + prev.getEntityKey())) continue;
      if (!isObservedKey(prev, activeIps, activeMacsLower)) continue; // absent in this snapshot

      Map<String, Object> observed =
          computeProperties(prev.getEntityType(), prev.getEntityKey(), newFileId);
      Map<String, Object> baseline = prev.getObservedProperties();
      List<String> changes =
          (baseline == null || baseline.isEmpty()) ? List.of() : diff(baseline, observed);

      NodeRoleEntity carried =
          NodeRoleEntity.builder()
              .fileId(newFileId)
              .entityType(prev.getEntityType())
              .entityKey(prev.getEntityKey())
              .roleLabel(prev.getRoleLabel())
              .roleDescription(prev.getRoleDescription())
              .origin(ORIGIN_CARRIED_FORWARD)
              .llmSuggested(false)
              .confirmedByHuman(true)
              .observedProperties(observed)
              .build();
      if (!changes.isEmpty()) {
        carried.setStaleSince(LocalDateTime.now());
        carried.setStaleFields(changes);
        drifts.add(
            new LabelDrift(
                prev.getEntityType(), prev.getEntityKey(), prev.getRoleLabel(), changes));
      }
      nodeRoleRepository.save(carried);
    }
    return drifts;
  }

  /** True when the role's entity (IP or MAC) is among the file's classified hosts. */
  private boolean isObservedKey(
      NodeRoleEntity role, Set<String> activeIps, Set<String> activeMacsLower) {
    String key = role.getEntityKey();
    if (key == null) return false;
    if ("DEVICE".equalsIgnoreCase(role.getEntityType()))
      return activeMacsLower.contains(key.toLowerCase());
    return activeIps.contains(key);
  }

  // ── Property computation ──────────────────────────────────────────────────────

  /**
   * Snapshots a node's key properties from a file: MAC, device type, dominant protocols and
   * external orgs contacted. {@code observed} is true when the node appears in the file at all.
   */
  Map<String, Object> computeProperties(String entityType, String entityKey, UUID fileId) {
    Map<String, Object> props = new HashMap<>();
    props.put("observed", false);

    String ip = null;
    if ("IP".equalsIgnoreCase(entityType)) {
      ip = entityKey;
      hostClassificationRepository
          .findByFileIdAndIp(fileId, entityKey)
          .ifPresent(
              h -> {
                props.put("observed", true);
                if (h.getMac() != null) props.put("mac", h.getMac());
                if (h.getDeviceType() != null) props.put("deviceType", h.getDeviceType());
              });
    } else if ("DEVICE".equalsIgnoreCase(entityType)) {
      props.put("mac", entityKey);
      Optional<com.tracepcap.analysis.entity.HostClassificationEntity> host =
          hostClassificationRepository.findByFileIdAndMacIgnoreCase(fileId, entityKey);
      if (host.isPresent()) {
        props.put("observed", true);
        ip = host.get().getIp();
        if (host.get().getDeviceType() != null) props.put("deviceType", host.get().getDeviceType());
      }
    }

    if (ip != null) {
      List<String> protocols = topProtocols(fileId, ip);
      List<String> orgs = externalOrgs(fileId, ip);
      props.put("protocols", protocols);
      props.put("orgs", orgs);
      // Conversations alone are enough to consider the node observed (e.g. no host classification).
      if (!protocols.isEmpty() || !orgs.isEmpty()) props.put("observed", true);
    }
    return props;
  }

  private List<String> topProtocols(UUID fileId, String ip) {
    String sql =
        """
        SELECT tshark_protocol
        FROM conversations
        WHERE file_id = ? AND (src_ip = ? OR dst_ip = ?)
          AND tshark_protocol IS NOT NULL
        GROUP BY tshark_protocol ORDER BY COUNT(*) DESC LIMIT 5
        """;
    try {
      return jdbc.query(sql, (rs, i) -> rs.getString(1), fileId, ip, ip).stream()
          .filter(p -> p != null && !p.isBlank())
          .map(String::toUpperCase)
          .collect(Collectors.toList());
    } catch (Exception e) {
      log.debug("Could not load protocols for {} in {}: {}", ip, fileId, e.getMessage());
      return List.of();
    }
  }

  /**
   * Cap on the number of distinct peers we resolve geo orgs for. A single node in a busy network
   * (or during a scan) can talk to tens of thousands of peers, which would blow past DB parameter
   * limits and slow the query — the distinct org set stabilises well before this bound.
   */
  private static final int MAX_PEERS_FOR_GEO = 1000;

  private List<String> externalOrgs(UUID fileId, String ip) {
    String sql =
        """
        SELECT DISTINCT CASE WHEN src_ip = ? THEN dst_ip ELSE src_ip END AS peer
        FROM conversations
        WHERE file_id = ? AND (src_ip = ? OR dst_ip = ?)
        LIMIT ?
        """;
    Set<String> peers;
    try {
      peers =
          new LinkedHashSet<>(
              jdbc.query(sql, (rs, i) -> rs.getString(1), ip, fileId, ip, ip, MAX_PEERS_FOR_GEO));
    } catch (Exception e) {
      log.debug("Could not load peers for {} in {}: {}", ip, fileId, e.getMessage());
      return List.of();
    }
    peers.remove(ip);
    peers.remove(null);
    if (peers.isEmpty()) return List.of();
    return geoOrgs(peers);
  }

  /**
   * Distinct non-blank org names for the geo records of the given IPs (proxy for external orgs).
   */
  private List<String> geoOrgs(Collection<String> ips) {
    return ipGeoInfoRepository.findAllByIpIn(ips).stream()
        .map(IpGeoInfoEntity::getOrg)
        .filter(o -> o != null && !o.isBlank())
        .distinct()
        .collect(Collectors.toList());
  }

  // ── Diffing ───────────────────────────────────────────────────────────────────

  private List<String> diff(Map<String, Object> baseline, Map<String, Object> current) {
    List<String> changes = new ArrayList<>();

    String baseMac = str(baseline.get("mac"));
    String curMac = str(current.get("mac"));
    if (!baseMac.isBlank() && !curMac.isBlank() && !baseMac.equalsIgnoreCase(curMac)) {
      changes.add("MAC changed (" + baseMac + " → " + curMac + ")");
    }

    List<String> newProtos =
        added(asList(baseline.get("protocols")), asList(current.get("protocols")));
    if (!newProtos.isEmpty()) {
      changes.add(
          "new protocol"
              + (newProtos.size() > 1 ? "s" : "")
              + " ("
              + String.join(", ", newProtos)
              + ")");
    }

    List<String> newOrgs = added(asList(baseline.get("orgs")), asList(current.get("orgs")));
    if (!newOrgs.isEmpty()) {
      changes.add(
          "new external org"
              + (newOrgs.size() > 1 ? "s" : "")
              + " ("
              + String.join(", ", newOrgs)
              + ")");
    }

    return changes;
  }

  /** Elements present in current but not baseline (case-insensitive), preserving current order. */
  private List<String> added(List<String> baseline, List<String> current) {
    Set<String> baseLower = baseline.stream().map(s -> s.toLowerCase()).collect(Collectors.toSet());
    return current.stream()
        .filter(c -> !baseLower.contains(c.toLowerCase()))
        .distinct()
        .collect(Collectors.toList());
  }

  @SuppressWarnings("unchecked")
  private List<String> asList(Object o) {
    if (o instanceof List<?> list) {
      return list.stream()
          .filter(x -> x != null)
          .map(Object::toString)
          .collect(Collectors.toList());
    }
    return List.of();
  }

  private String str(Object o) {
    return o == null ? "" : o.toString();
  }
}
