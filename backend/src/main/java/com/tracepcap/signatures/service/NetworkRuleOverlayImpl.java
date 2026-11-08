package com.tracepcap.signatures.service;

import com.tracepcap.analysis.spi.NetworkRuleOverlay;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Reads a network's rule matches for one capture from rule_matches (#925 phase 3). For a capture
 * outside the network, the rules are checked first, on demand.
 */
@Component
@RequiredArgsConstructor
class NetworkRuleOverlayImpl implements NetworkRuleOverlay {

  private final JdbcTemplate jdbc;
  private final RuleSyncService ruleSync;

  @Override
  public Map<UUID, List<String>> labels(UUID networkId, UUID fileId) {
    ruleSync.ensureCheckedForViewing(networkId, fileId);
    Map<UUID, List<String>> out = new LinkedHashMap<>();
    jdbc.query(
        "SELECT m.conversation_id, r.name FROM rule_matches m JOIN detection_rules r ON r.id = m.rule_id"
            + " WHERE r.scope = 'NETWORK' AND r.network_id = ? AND r.enabled AND m.file_id = ?"
            + " ORDER BY m.conversation_id, r.name",
        rs -> {
          out.computeIfAbsent(rs.getObject(1, UUID.class), k -> new ArrayList<>()).add(rs.getString(2));
        },
        networkId,
        fileId);
    return out;
  }

  @Override
  public Set<UUID> conversationsMatching(UUID networkId, UUID fileId, Collection<String> names) {
    Set<UUID> out = new HashSet<>();
    if (names == null || names.isEmpty()) return out;
    ruleSync.ensureCheckedForViewing(networkId, fileId);
    String[] arr = names.toArray(String[]::new);
    jdbc.query(
        con -> {
          PreparedStatement ps =
              con.prepareStatement(
                  "SELECT DISTINCT m.conversation_id FROM rule_matches m JOIN detection_rules r ON r.id = m.rule_id"
                      + " WHERE r.scope = 'NETWORK' AND r.network_id = ? AND r.enabled AND m.file_id = ?"
                      + " AND r.name = ANY (?)");
          ps.setObject(1, networkId);
          ps.setObject(2, fileId);
          ps.setArray(3, con.createArrayOf("text", arr));
          return ps;
        },
        rs -> {
          out.add(rs.getObject(1, UUID.class));
        });
    return out;
  }
}
