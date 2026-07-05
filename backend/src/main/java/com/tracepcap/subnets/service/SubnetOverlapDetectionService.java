package com.tracepcap.subnets.service;

import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import com.tracepcap.subnets.dto.SubnetOverlapWarningDto;
import com.tracepcap.subnets.entity.SubnetDefinitionEntity;
import com.tracepcap.subnets.repository.SubnetDefinitionRepository;
import java.util.ArrayList;
import java.util.Comparator;
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
 * per IP (unlike {@code host_classifications}, which is one MAC per IP). A subnet is flagged only
 * when one of its member IPs shows this conflict in the network's latest snapshot; otherwise nothing
 * is returned. Absence of a warning is not a claim that the CIDR is a single network — only that we
 * have no evidence to the contrary.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SubnetOverlapDetectionService {

  private final SubnetDefinitionRepository subnetRepo;
  private final NetworkSnapshotRepository snapshotRepo;
  private final JdbcTemplate jdbc;

  /**
   * Overlap warnings for every defined subnet, evaluated against a network's latest snapshot. Only
   * subnets with a member IP claimed by multiple MACs are returned; a clean subnet yields nothing.
   */
  public List<SubnetOverlapWarningDto> detect(UUID networkId) {
    UUID fileId = latestFileId(networkId);
    if (fileId == null) return List.of();

    // IP -> distinct MACs, only for IPs with a conflict (>1 MAC) in this file.
    Map<String, List<String>> conflicts = conflictingIpMacs(fileId);
    if (conflicts.isEmpty()) return List.of();

    List<SubnetOverlapWarningDto> warnings = new ArrayList<>();
    for (SubnetDefinitionEntity subnet : subnetRepo.findAll()) {
      long[] range;
      try {
        range = CidrRange.of(subnet.getCidr());
      } catch (Exception e) {
        continue;
      }
      // The first conflicting IP that falls inside this CIDR is enough to flag it.
      for (Map.Entry<String, List<String>> e : conflicts.entrySet()) {
        Long ipInt = ipToLongOrNull(e.getKey());
        if (ipInt == null || ipInt < range[0] || ipInt > range[1]) continue;
        warnings.add(
            SubnetOverlapWarningDto.builder()
                .subnetId(subnet.getId())
                .cidr(subnet.getCidr())
                .conflictingIp(e.getKey())
                .macs(e.getValue())
                .build());
        break;
      }
    }
    return warnings;
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

  private UUID latestFileId(UUID networkId) {
    if (networkId == null) return null;
    return snapshotRepo.findByNetworkIdOrderBySnapshotOrderAsc(networkId).stream()
        .filter(s -> s.getFile() != null)
        .max(Comparator.comparingInt(NetworkSnapshotEntity::getSnapshotOrder))
        .map(s -> s.getFile().getId())
        .orElse(null);
  }

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
