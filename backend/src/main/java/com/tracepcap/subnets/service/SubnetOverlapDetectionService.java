package com.tracepcap.subnets.service;

import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import com.tracepcap.subnets.dto.SubnetOverlapWarningDto;
import com.tracepcap.subnets.entity.SubnetDefinitionEntity;
import com.tracepcap.subnets.repository.SubnetDefinitionRepository;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Detects the unambiguous tell that a CIDR is really two different L2 networks sharing the same range
 * (#461): within a single capture, an <b>IP claimed by more than one MAC</b>. There is no benign
 * reason for two devices to answer for the same IP at once — that is what overlapping networks look
 * like at layer 2.
 *
 * <p>The signal lives in {@code ip_mac_observations}, which retains every distinct source MAC seen
 * per IP (unlike {@code host_classifications}, which is one MAC per IP). A subnet is flagged when one
 * of its member IPs shows this conflict in <b>any</b> snapshot of the network — overlaps are often
 * transient (a shadow device that appears then leaves), so a latest-snapshot-only check would miss
 * them. The warning names the snapshot where the conflict was seen. Absence of a warning is not a
 * claim that the CIDR is a single network — only that we have no evidence to the contrary.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SubnetOverlapDetectionService {

  private final SubnetDefinitionRepository subnetRepo;
  private final NetworkSnapshotRepository snapshotRepo;
  private final JdbcTemplate jdbc;

  /**
   * Overlap warnings for every defined subnet, evaluated across <b>all</b> of a network's snapshots.
   * At most one warning per subnet — the earliest snapshot exhibiting a conflict. Clean subnets
   * yield nothing.
   */
  public List<SubnetOverlapWarningDto> detect(UUID networkId) {
    if (networkId == null) return List.of();

    List<SubnetDefinitionEntity> subnets = subnetRepo.findAll();
    if (subnets.isEmpty()) return List.of();

    // Precompute CIDR integer ranges once.
    Map<SubnetDefinitionEntity, long[]> ranges = new LinkedHashMap<>();
    for (SubnetDefinitionEntity s : subnets) {
      try {
        ranges.put(s, CidrRange.of(s.getCidr()));
      } catch (Exception ignored) {
        // skip malformed CIDR
      }
    }

    Map<Long, SubnetOverlapWarningDto> bySubnet = new LinkedHashMap<>();
    // Walk snapshots in order so the first conflict found per subnet is the earliest one.
    for (NetworkSnapshotEntity snap :
        snapshotRepo.findByNetworkIdWithFileOrderBySnapshotOrderAsc(networkId)) {
      if (snap.getFile() == null) continue;
      Map<String, List<String>> conflicts = conflictingIpMacs(snap.getFile().getId());
      if (conflicts.isEmpty()) continue;

      for (Map.Entry<SubnetDefinitionEntity, long[]> re : ranges.entrySet()) {
        SubnetDefinitionEntity subnet = re.getKey();
        if (bySubnet.containsKey(subnet.getId())) continue; // already flagged from an earlier snapshot
        long[] range = re.getValue();
        for (Map.Entry<String, List<String>> c : conflicts.entrySet()) {
          Long ipInt = ipToLongOrNull(c.getKey());
          if (ipInt == null || ipInt < range[0] || ipInt > range[1]) continue;
          bySubnet.put(
              subnet.getId(),
              SubnetOverlapWarningDto.builder()
                  .subnetId(subnet.getId())
                  .cidr(subnet.getCidr())
                  .conflictingIp(c.getKey())
                  .macs(c.getValue())
                  .snapshotOrder(snap.getSnapshotOrder())
                  .snapshotFileName(snap.getFile().getFileName())
                  .build());
          break;
        }
      }
    }
    return new ArrayList<>(bySubnet.values());
  }

  /** IPs in a file observed with more than one distinct MAC → {ip: [macs]}. */
  private Map<String, List<String>> conflictingIpMacs(UUID fileId) {
    Map<String, List<String>> byIp = new LinkedHashMap<>();
    try {
      jdbc.query(
          con -> {
            var ps =
                con.prepareStatement(
                    """
                    SELECT ip, mac FROM ip_mac_observations
                    WHERE file_id = ?
                      AND ip IN (
                        SELECT ip FROM ip_mac_observations
                        WHERE file_id = ? GROUP BY ip HAVING COUNT(DISTINCT mac) > 1
                      )
                    ORDER BY ip, mac
                    """);
            ps.setObject(1, fileId);
            ps.setObject(2, fileId);
            return ps;
          },
          rs -> {
            byIp.computeIfAbsent(rs.getString("ip"), k -> new ArrayList<>()).add(rs.getString("mac"));
          });
    } catch (Exception e) {
      log.warn("Conflicting IP/MAC lookup failed for file {}: {}", fileId, e.getMessage());
      return Map.of();
    }
    return byIp;
  }

  // ── helpers ───────────────────────────────────────────────────────────────

  private static Long ipToLongOrNull(String ip) {
    try {
      String[] o = ip.split("\\.");
      if (o.length != 4) return null;
      long v = 0;
      for (String part : o) {
        int oct = Integer.parseInt(part);
        if (oct < 0 || oct > 255) return null;
        v = (v << 8) | oct;
      }
      return v;
    } catch (NumberFormatException e) {
      return null;
    }
  }
}
