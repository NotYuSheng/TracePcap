package com.tracepcap.insights.service;

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
 * Captures a baseline of a node's key properties when a human confirms its role label, and detects
 * when those properties later drift (#369). Drift on MAC, dominant protocols, or external orgs marks
 * the label stale so the analyst can re-confirm or update it.
 *
 * <p>Lives in the insights package and returns plain {@link LabelDrift} descriptors so the monitor
 * change-detection flow can raise events without this service depending on monitor types.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LabelStalenessService {

  private final NodeRoleRepository nodeRoleRepository;
  private final HostClassificationRepository hostClassificationRepository;
  private final IpGeoInfoRepository ipGeoInfoRepository;
  private final JdbcTemplate jdbc;

  /**
   * Records the current node properties as the drift baseline for a confirmed label.
   *
   * @param updateLabeledAt true when the human just (re)set the label; false when merely dismissing
   *     a stale warning (the original label time is kept, only the baseline is refreshed).
   */
  @Transactional
  public void captureBaseline(NodeRoleEntity entity, UUID fileId, boolean updateLabeledAt) {
    if (fileId == null) return;
    entity.setBaselineFileId(fileId);
    entity.setBaselineProperties(computeProperties(entity.getEntityType(), entity.getEntityKey(), fileId));
    entity.setStaleSince(null);
    entity.setStaleFields(null);
    if (updateLabeledAt || entity.getLabeledAt() == null) {
      entity.setLabeledAt(LocalDateTime.now());
    }
    nodeRoleRepository.save(entity);
  }

  /** Clears a stale flag and re-baselines from the dismissed-at file context. */
  @Transactional
  public void dismiss(String entityType, String entityKey, UUID fileId) {
    nodeRoleRepository
        .findByEntityTypeAndEntityKey(entityType, entityKey)
        .ifPresent(e -> captureBaseline(e, fileId, false));
  }

  /**
   * For every confirmed label with a baseline whose node is observed in {@code fileId}, compares
   * current properties against the baseline. When drift is found and the label is not already stale,
   * sets {@code staleSince}/{@code staleFields}. Returns a descriptor for each newly-stale label.
   */
  @Transactional
  public List<LabelDrift> detectAndMarkDrift(UUID fileId) {
    if (fileId == null) return List.of();
    List<LabelDrift> drifts = new ArrayList<>();

    for (NodeRoleEntity role : nodeRoleRepository.findByConfirmedByHumanTrue()) {
      Map<String, Object> baseline = role.getBaselineProperties();
      if (baseline == null || baseline.isEmpty()) continue;
      if (role.getStaleSince() != null) continue; // already flagged — don't re-fire

      Map<String, Object> current =
          computeProperties(role.getEntityType(), role.getEntityKey(), fileId);
      if (!Boolean.TRUE.equals(current.get("observed"))) continue; // node absent in this snapshot

      List<String> changes = diff(baseline, current);
      if (changes.isEmpty()) continue;

      role.setStaleSince(LocalDateTime.now());
      role.setStaleFields(changes);
      nodeRoleRepository.save(role);
      drifts.add(
          new LabelDrift(
              role.getEntityType(),
              role.getEntityKey(),
              role.getRoleLabel(),
              role.getLabeledAt(),
              changes));
    }
    return drifts;
  }

  // ── Property computation ──────────────────────────────────────────────────────

  /**
   * Snapshots a node's key properties from a file: MAC, device type, dominant protocols and external
   * orgs contacted. {@code observed} is true when the node appears in the file at all.
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
        WHERE (file_id = ? AND src_ip = ? OR file_id = ? AND dst_ip = ?)
          AND tshark_protocol IS NOT NULL
        GROUP BY tshark_protocol ORDER BY COUNT(*) DESC LIMIT 5
        """;
    try {
      return jdbc.query(sql, (rs, i) -> rs.getString(1), fileId, ip, fileId, ip).stream()
          .filter(p -> p != null && !p.isBlank())
          .map(String::toUpperCase)
          .collect(Collectors.toList());
    } catch (Exception e) {
      log.debug("Could not load protocols for {} in {}: {}", ip, fileId, e.getMessage());
      return List.of();
    }
  }

  private List<String> externalOrgs(UUID fileId, String ip) {
    String sql =
        """
        SELECT DISTINCT peer FROM (
          SELECT dst_ip AS peer FROM conversations WHERE file_id = ? AND src_ip = ?
          UNION
          SELECT src_ip AS peer FROM conversations WHERE file_id = ? AND dst_ip = ?
        ) t WHERE peer IS NOT NULL
        """;
    Set<String> peers;
    try {
      peers = new LinkedHashSet<>(jdbc.query(sql, (rs, i) -> rs.getString(1), fileId, ip, fileId, ip));
    } catch (Exception e) {
      log.debug("Could not load peers for {} in {}: {}", ip, fileId, e.getMessage());
      return List.of();
    }
    peers.remove(ip);
    if (peers.isEmpty()) return List.of();
    return geoOrgs(peers);
  }

  /** Distinct non-blank org names for the geo records of the given IPs (proxy for external orgs). */
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

    List<String> newProtos = added(asList(baseline.get("protocols")), asList(current.get("protocols")));
    if (!newProtos.isEmpty()) {
      changes.add("new protocol" + (newProtos.size() > 1 ? "s" : "") + " (" + String.join(", ", newProtos) + ")");
    }

    List<String> newOrgs = added(asList(baseline.get("orgs")), asList(current.get("orgs")));
    if (!newOrgs.isEmpty()) {
      changes.add("new external org" + (newOrgs.size() > 1 ? "s" : "") + " (" + String.join(", ", newOrgs) + ")");
    }

    return changes;
  }

  /** Elements present in current but not baseline (case-insensitive), preserving current order. */
  private List<String> added(List<String> baseline, List<String> current) {
    Set<String> baseLower =
        baseline.stream().map(s -> s.toLowerCase()).collect(Collectors.toSet());
    return current.stream()
        .filter(c -> !baseLower.contains(c.toLowerCase()))
        .distinct()
        .collect(Collectors.toList());
  }

  @SuppressWarnings("unchecked")
  private List<String> asList(Object o) {
    if (o instanceof List<?> list) {
      return list.stream().filter(x -> x != null).map(Object::toString).collect(Collectors.toList());
    }
    return List.of();
  }

  private String str(Object o) {
    return o == null ? "" : o.toString();
  }
}
