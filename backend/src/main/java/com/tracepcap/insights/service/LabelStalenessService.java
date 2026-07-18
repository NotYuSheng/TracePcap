package com.tracepcap.insights.service;

import com.tracepcap.analysis.spi.GeoOrgLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.common.adjudication.HumanOverrideEntity;
import com.tracepcap.common.adjudication.HumanOverrideRepository;
import com.tracepcap.monitor.spi.LabelStalenessCheck;
import com.tracepcap.insights.entity.NodeRoleEntity;
import com.tracepcap.insights.repository.NodeRoleRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
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
 * Per-file node-role property + staleness logic (#369). Roles live per file (a monitor snapshot is
 * a file). When a new snapshot is added, each confirmed classification on the previous snapshot is
 * carried forward and validated against the new pcap's observed properties; drift on MAC, dominant
 * protocols, or external orgs flags the carried label stale.
 *
 * <p>Implements monitor's {@link LabelStalenessCheck} port (#512 slice 3): the monitor
 * change-detection flow calls the port, and the dependency points insights → monitor — never the
 * reverse — keeping the two modules acyclic.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LabelStalenessService implements LabelStalenessCheck {

  public static final String ORIGIN_CARRIED_FORWARD = "CARRIED_FORWARD";

  /** Adjudication questions whose human overrides carry forward + go stale in monitor mode (#499). */
  private static final List<String> OVERRIDE_QUESTIONS =
      List.of("host-identity", "host-hardware", "host-service", "host-behaviour");

  private final NodeRoleRepository nodeRoleRepository;
  private final HumanOverrideRepository humanOverrideRepository;
  private final HostClassificationLookup hostClassificationLookup;
  private final GeoOrgLookup geoOrgLookup;
  private final JdbcTemplate jdbc;

  /**
   * Carries each confirmed classification on {@code prevFileId} forward onto {@code newFileId} and
   * validates it against the new pcap. Carried rows (origin {@code CARRIED_FORWARD}) for the new
   * file are regenerated each call; entities the analyst has labelled directly on the new file
   * (origin {@code MANUAL}/{@code AI}) are left untouched and take precedence. Returns a descriptor
   * for each carried label that drifted from its baseline.
   */
  @Transactional
  @Override
  public List<Drift> carryForwardAndValidate(UUID prevFileId, UUID newFileId) {
    if (newFileId == null) return List.of();
    // Always clear stale carried rows — roles AND overrides — so a reorder/re-add regenerates
    // cleanly, and so a file disconnected from any predecessor (prevFileId null) doesn't keep
    // carried overrides standing from whatever it was previously chained to.
    nodeRoleRepository.deleteByFileIdAndOrigin(newFileId, ORIGIN_CARRIED_FORWARD);
    for (String question : OVERRIDE_QUESTIONS) {
      humanOverrideRepository.deleteByQuestionAndFileIdAndOrigin(
          question, newFileId, ORIGIN_CARRIED_FORWARD);
    }
    if (prevFileId == null) return List.of();

    List<Drift> drifts = new ArrayList<>();
    // Overrides carry independently of node roles — a network can have adjudication overrides and
    // not a single confirmed role, and an early return on the role branch used to silently skip
    // every carried override.
    drifts.addAll(carryForwardOverrides(prevFileId, newFileId));

    List<NodeRoleEntity> confirmed =
        nodeRoleRepository.findByFileIdAndConfirmedByHumanTrue(prevFileId);
    if (confirmed.isEmpty()) return drifts;

    // Entities already labelled directly on the new file — don't overwrite them.
    Set<String> ownKeys =
        nodeRoleRepository.findByFileId(newFileId).stream()
            .filter(r -> !ORIGIN_CARRIED_FORWARD.equals(r.getOrigin()))
            .map(r -> r.getEntityType() + "|" + r.getEntityKey())
            .collect(Collectors.toSet());

    for (NodeRoleEntity prev : confirmed) {
      if (ownKeys.contains(prev.getEntityType() + "|" + prev.getEntityKey())) continue;

      // computeProperties' own "observed" flag also covers IPs seen only in conversations
      // (no host_classifications row), which a host-classification-only pre-filter would miss.
      Map<String, Object> observed =
          computeProperties(prev.getEntityType(), prev.getEntityKey(), newFileId);
      if (!Boolean.TRUE.equals(observed.get("observed"))) continue; // absent in this snapshot

      Map<String, Object> baseline = prev.getObservedProperties();
      List<String> changes =
          (baseline == null || baseline.isEmpty()) ? List.of() : diff(baseline, observed);

      // Preserve an unresolved stale marker across snapshots: staleness only clears when the analyst
      // dismisses or re-labels (which creates a MANUAL row), not just because a later snapshot adds
      // no *new* drift beyond the previous one.
      LocalDateTime staleSince = null;
      List<String> staleFields = null;
      if (!changes.isEmpty()) {
        staleSince = prev.getStaleSince() != null ? prev.getStaleSince() : LocalDateTime.now();
        staleFields = changes;
        drifts.add(
            new Drift(
                prev.getEntityType(), prev.getEntityKey(), prev.getRoleLabel(), changes));
      } else if (prev.getStaleSince() != null) {
        staleSince = prev.getStaleSince();
        staleFields = prev.getStaleFields();
      }

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
              // Carry the original annotator forward — the confirmation is theirs, not this run's.
              .confirmedBy(prev.getConfirmedBy())
              .observedProperties(observed)
              .staleSince(staleSince)
              .staleFields(staleFields)
              .build();
      nodeRoleRepository.save(carried);
    }

    return drifts;
  }

  /**
   * Carries human adjudication overrides (host-identity + the evidence axes) forward from the
   * previous snapshot onto the new file and flags those whose classifying evidence drifted (#499).
   * Callers must first clear this file's existing CARRIED_FORWARD rows (done unconditionally in
   * {@link #carryForwardAndValidate}, ahead of the {@code prevFileId == null} short-circuit, so a
   * file disconnected from any predecessor still loses its carried overrides). Mirrors the
   * node-role carry-forward above: an override the analyst set directly on the new file (origin
   * MANUAL) is left untouched. Staleness is sticky — it persists until the analyst re-affirms or
   * clears the override.
   */
  private List<Drift> carryForwardOverrides(UUID prevFileId, UUID newFileId) {

    List<Drift> drifts = new ArrayList<>();
    for (String question : OVERRIDE_QUESTIONS) {
      List<HumanOverrideEntity> prevOverrides =
          humanOverrideRepository.findByQuestionAndFileId(question, prevFileId);
      if (prevOverrides.isEmpty()) continue;

      // Entities the analyst has overridden directly on the new file — don't overwrite them.
      Set<String> ownKeys =
          humanOverrideRepository.findByQuestionAndFileId(question, newFileId).stream()
              .filter(o -> !ORIGIN_CARRIED_FORWARD.equals(o.getOrigin()))
              .map(HumanOverrideEntity::getEntityKey)
              .collect(Collectors.toSet());

      for (HumanOverrideEntity prev : prevOverrides) {
        // Carried rows DO carry again: in a monitor chain each snapshot only sees its immediate
        // predecessor, so skipping CARRIED_FORWARD rows made an override vanish after one hop
        // (manual on A → carried to B → gone from C). The original actor and sticky staleness
        // ride along; the node-role carry above has always chained the same way.
        if (ownKeys.contains(prev.getEntityKey())) continue;

        // Overrides are keyed by IP (host-identity/axes are per-host). Reuse the IP property snapshot.
        Map<String, Object> observed = computeProperties("IP", prev.getEntityKey(), newFileId);
        if (!Boolean.TRUE.equals(observed.get("observed"))) continue; // absent in this snapshot

        // A MANUAL override set directly on the previous file has no stored baseline (unlike node
        // roles, the override endpoint doesn't snapshot one). Derive it from the previous file so the
        // first carry can still detect drift.
        Map<String, Object> baseline = prev.getObservedProperties();
        if (baseline == null || baseline.isEmpty()) {
          baseline = computeProperties("IP", prev.getEntityKey(), prevFileId);
        }
        List<String> changes =
            (baseline == null || baseline.isEmpty()) ? List.of() : diff(baseline, observed);

        LocalDateTime staleSince = null;
        List<String> staleFields = null;
        if (!changes.isEmpty()) {
          staleSince = prev.getStaleSince() != null ? prev.getStaleSince() : LocalDateTime.now();
          staleFields = changes;
          drifts.add(new Drift("IP", prev.getEntityKey(), prev.getLabel(), changes));
        } else if (prev.getStaleSince() != null) {
          staleSince = prev.getStaleSince();
          staleFields = prev.getStaleFields();
        }

        humanOverrideRepository.save(
            HumanOverrideEntity.builder()
                .question(question)
                .fileId(newFileId)
                .entityKey(prev.getEntityKey())
                .label(prev.getLabel())
                .rationale(prev.getRationale())
                .actor(prev.getActor())
                .origin(ORIGIN_CARRIED_FORWARD)
                .observedProperties(observed)
                .staleSince(staleSince)
                .staleFields(staleFields)
                .build());
      }
    }
    return drifts;
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
      hostClassificationLookup
          .hostFactsByIp(fileId, entityKey)
          .ifPresent(
              h -> {
                props.put("observed", true);
                if (h.mac() != null) props.put("mac", h.mac());
                if (h.deviceType() != null) props.put("deviceType", h.deviceType());
              });
    } else if ("DEVICE".equalsIgnoreCase(entityType)) {
      props.put("mac", entityKey);
      Optional<HostClassificationLookup.HostFacts> host =
          hostClassificationLookup.hostFactsByMac(fileId, entityKey);
      if (host.isPresent()) {
        props.put("observed", true);
        ip = host.get().ip();
        if (host.get().deviceType() != null) props.put("deviceType", host.get().deviceType());
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
    return geoOrgLookup.orgsFor(peers);
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
