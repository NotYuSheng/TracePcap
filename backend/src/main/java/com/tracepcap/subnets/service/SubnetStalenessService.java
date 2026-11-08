package com.tracepcap.subnets.service;

import com.tracepcap.subnets.entity.SubnetNetworkBaselineEntity;
import java.util.Optional;

import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import com.tracepcap.monitor.spi.SnapshotRevalidationHook;
import com.tracepcap.subnets.entity.SubnetDefinitionEntity;
import com.tracepcap.subnets.repository.SubnetDefinitionRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Composition-based staleness for subnet definitions (#363), mirroring the node-role model (#369).
 * A subnet's "composition" is the set of dominant member device types + protocols observed in a
 * file. When an analyst confirms a subnet's label we snapshot this composition as the baseline; each
 * new snapshot's composition is compared against it, and a drift (device types or protocols
 * appearing/leaving) flags the label stale until re-labelled or dismissed.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SubnetStalenessService implements SnapshotRevalidationHook {

  /** Distinct device types / protocols to keep as the subnet's dominant signature. */
  private static final int TOP_DEVICE_TYPES = 6;
  private static final int TOP_PROTOCOLS = 8;

  private final SubnetDefinitionRepository subnetRepo;
  private final com.tracepcap.subnets.repository.SubnetNetworkBaselineRepository baselineRepo;
  private final NetworkSnapshotRepository snapshotRepo;
  private final JdbcTemplate jdbc;

  /** One snapshot's view of a subnet: composition + the snapshot's identity. */
  public record CompositionHistoryEntry(
      UUID snapshotId,
      UUID fileId,
      String fileName,
      int snapshotOrder,
      int memberCount,
      List<String> deviceTypes,
      List<String> protocols) {}

  /**
   * Per-snapshot composition history for a subnet across a network's snapshots — only the snapshots
   * where the subnet had members. Feeds the subnet Snapshot History table (analogous to the IP one).
   */
  public List<CompositionHistoryEntry> history(String cidr, UUID networkId) {
    if (networkId == null) return List.of();
    List<CompositionHistoryEntry> out = new ArrayList<>();
    // Fetch-join the file so getFileName() works outside a session (this method isn't @Transactional).
    for (NetworkSnapshotEntity snap :
        snapshotRepo.findByNetworkIdWithFileOrderBySnapshotOrderAsc(networkId)) {
      if (snap.getFile() == null) continue;
      Map<String, Object> comp = computeComposition(cidr, snap.getFile().getId());
      if (!Boolean.TRUE.equals(comp.get("observed"))) continue;
      out.add(
          new CompositionHistoryEntry(
              snap.getId(),
              snap.getFile().getId(),
              snap.getFile().getFileName(),
              snap.getSnapshotOrder(),
              (int) comp.getOrDefault("memberCount", 0),
              asList(comp.get("deviceTypes")),
              asList(comp.get("protocols"))));
    }
    return out;
  }

  @SuppressWarnings("unchecked")
  private List<String> asList(Object raw) {
    return raw instanceof List<?> l
        ? l.stream().filter(o -> o != null).map(Object::toString).collect(Collectors.toList())
        : List.of();
  }

  /**
   * Snapshot a subnet's composition from a file: dominant member device types + protocols and the
   * member count. {@code observed} is true when any member host appears in the file.
   */
  public Map<String, Object> computeComposition(String cidr, UUID fileId) {
    Map<String, Object> comp = new HashMap<>();
    comp.put("observed", false);
    comp.put("deviceTypes", List.of());
    comp.put("protocols", List.of());
    comp.put("memberCount", 0);
    if (fileId == null) return comp;

    long[] range;
    try {
      range = CidrRange.of(cidr);
    } catch (Exception e) {
      return comp;
    }

    List<String> memberIps = memberIps(fileId, range[0], range[1]);
    if (memberIps.isEmpty()) return comp;

    comp.put("observed", true);
    comp.put("memberCount", memberIps.size());
    comp.put("deviceTypes", dominantDeviceTypes(fileId, range[0], range[1]));
    comp.put("protocols", dominantProtocols(fileId, range[0], range[1]));
    return comp;
  }

  /**
   * Capture the current composition of a subnet as its staleness baseline in a network, from that
   * network's latest snapshot. Called when an analyst confirms the label. Baselines are per network
   * (#915 phase 4): with no network there's nothing to compare against, so nothing is recorded.
   */
  @Transactional
  public void captureBaseline(SubnetDefinitionEntity subnet, UUID networkId) {
    UUID fileId = latestFileId(networkId);
    if (fileId == null || subnet.getId() == null) {
      // No snapshot to baseline against (no networkId, or an empty network). The label is saved,
      // but the subnet can never be flagged stale. The UI always passes networkId, so this is an
      // API caller that omitted it. Logged so "why is this subnet never stale?" has an answer (#465).
      log.info(
          "Subnet {} ({}) labelled without a staleness baseline: no snapshot for network {}",
          subnet.getId(), subnet.getCidr(), networkId);
      return;
    }
    Map<String, Object> comp = computeComposition(subnet.getCidr(), fileId);
    SubnetNetworkBaselineEntity b =
        baselineRepo
            .findBySubnetIdAndNetworkId(subnet.getId(), networkId)
            .orElseGet(() -> SubnetNetworkBaselineEntity.builder().subnetId(subnet.getId()).networkId(networkId).build());
    b.setLabeledAt(LocalDateTime.now());
    b.setBaselineFileId(fileId);
    b.setBaselineComposition(Boolean.TRUE.equals(comp.get("observed")) ? comp : null);
    b.setStaleSince(null);
    b.setStaleFields(null);
    baselineRepo.save(b);
  }

  /** A subnet's baseline in a network, if it has one. */
  public Optional<SubnetNetworkBaselineEntity> baseline(Long subnetId, UUID networkId) {
    if (subnetId == null || networkId == null) return Optional.empty();
    return baselineRepo.findBySubnetIdAndNetworkId(subnetId, networkId);
  }

  /**
   * Re-validate every labelled subnet against the latest snapshot of a network: recompute each
   * subnet's composition and, if it has drifted from its baseline in this network, flag it stale.
   * Called by monitor change detection through the {@code SnapshotRevalidationHook} port after a
   * snapshot is added/reordered (#512 slice 3). No-op for subnets without a baseline here.
   */
  @Override
  @Transactional
  public void revalidate(UUID networkId) {
    UUID fileId = latestFileId(networkId);
    if (fileId == null) return;
    Map<Long, SubnetDefinitionEntity> byId = new HashMap<>();
    subnetRepo.findAllById(
            baselineRepo.findByNetworkId(networkId).stream().map(SubnetNetworkBaselineEntity::getSubnetId).toList())
        .forEach(sd -> byId.put(sd.getId(), sd));
    for (SubnetNetworkBaselineEntity b : baselineRepo.findByNetworkId(networkId)) {
      SubnetDefinitionEntity subnet = byId.get(b.getSubnetId());
      if (subnet == null || b.getBaselineComposition() == null || b.getLabeledAt() == null) continue;
      Map<String, Object> current = computeComposition(subnet.getCidr(), fileId);
      if (!Boolean.TRUE.equals(current.get("observed"))) continue; // subnet absent in this snapshot
      List<String> changes = diff(b.getBaselineComposition(), current);
      if (!changes.isEmpty()) {
        if (b.getStaleSince() == null) b.setStaleSince(LocalDateTime.now());
        b.setStaleFields(changes);
        baselineRepo.save(b);
      }
    }
  }

  // ── composition queries ─────────────────────────────────────────────────────

  private List<String> memberIps(UUID fileId, long lo, long hi) {
    try {
      return jdbc.query(
          con -> {
            var ps =
                con.prepareStatement(
                    """
                    SELECT DISTINCT ip FROM host_classifications
                    WHERE file_id = ? AND ip_to_int(ip) BETWEEN ? AND ?
                    """);
            ps.setObject(1, fileId);
            ps.setLong(2, lo);
            ps.setLong(3, hi);
            return ps;
          },
          (rs, i) -> rs.getString("ip"));
    } catch (Exception e) {
      log.warn("member IP lookup failed: {}", e.getMessage());
      return List.of();
    }
  }

  private List<String> dominantDeviceTypes(UUID fileId, long lo, long hi) {
    try {
      return jdbc.query(
          con -> {
            var ps =
                con.prepareStatement(
                    """
                    SELECT device_type FROM host_classifications
                    WHERE file_id = ? AND ip_to_int(ip) BETWEEN ? AND ?
                      AND device_type IS NOT NULL
                    GROUP BY device_type ORDER BY COUNT(*) DESC LIMIT ?
                    """);
            ps.setObject(1, fileId);
            ps.setLong(2, lo);
            ps.setLong(3, hi);
            ps.setInt(4, TOP_DEVICE_TYPES);
            return ps;
          },
          (rs, i) -> rs.getString("device_type"));
    } catch (Exception e) {
      log.warn("device-type composition failed: {}", e.getMessage());
      return List.of();
    }
  }

  private List<String> dominantProtocols(UUID fileId, long lo, long hi) {
    try {
      return jdbc
          .query(
              con -> {
                var ps =
                    con.prepareStatement(
                        """
                        SELECT tshark_protocol FROM conversations
                        WHERE file_id = ?
                          AND (ip_to_int(src_ip) BETWEEN ? AND ? OR ip_to_int(dst_ip) BETWEEN ? AND ?)
                          AND tshark_protocol IS NOT NULL
                        GROUP BY tshark_protocol ORDER BY COUNT(*) DESC LIMIT ?
                        """);
                ps.setObject(1, fileId);
                ps.setLong(2, lo);
                ps.setLong(3, hi);
                ps.setLong(4, lo);
                ps.setLong(5, hi);
                ps.setInt(6, TOP_PROTOCOLS);
                return ps;
              },
              (rs, i) -> rs.getString("tshark_protocol"))
          .stream()
          .filter(p -> p != null && !p.isBlank())
          .map(String::toUpperCase)
          .collect(Collectors.toList());
    } catch (Exception e) {
      log.warn("protocol composition failed: {}", e.getMessage());
      return List.of();
    }
  }

  // ── drift ─────────────────────────────────────────────────────────────────

  /** Human-readable list of composition changes between a baseline and current snapshot. */
  @SuppressWarnings("unchecked")
  private List<String> diff(Map<String, Object> baseline, Map<String, Object> current) {
    List<String> changes = new ArrayList<>();
    changes.addAll(
        setDiff(
            "device type",
            asStrings(baseline.get("deviceTypes")),
            asStrings(current.get("deviceTypes"))));
    changes.addAll(
        setDiff(
            "protocol",
            asStrings(baseline.get("protocols")),
            asStrings(current.get("protocols"))));
    return changes;
  }

  private List<String> setDiff(String noun, Set<String> base, Set<String> now) {
    List<String> out = new ArrayList<>();
    Set<String> added = new LinkedHashSet<>(now);
    added.removeAll(base);
    Set<String> removed = new LinkedHashSet<>(base);
    removed.removeAll(now);
    for (String a : added) out.add(noun + " appeared: " + a);
    for (String r : removed) out.add(noun + " gone: " + r);
    return out;
  }

  @SuppressWarnings("unchecked")
  private Set<String> asStrings(Object raw) {
    if (!(raw instanceof List<?> list)) return Set.of();
    return list.stream().filter(o -> o != null).map(Object::toString).collect(Collectors.toCollection(LinkedHashSet::new));
  }

  // ── helpers ─────────────────────────────────────────────────────────────────

  /** File id of the most recent snapshot of a network, or null. */
  private UUID latestFileId(UUID networkId) {
    if (networkId == null) return null;
    return snapshotRepo.findByNetworkIdOrderBySnapshotOrderAsc(networkId).stream()
        .filter(s -> s.getFile() != null)
        .max(Comparator.comparingInt(NetworkSnapshotEntity::getSnapshotOrder))
        .map(s -> s.getFile().getId())
        .orElse(null);
  }

}
