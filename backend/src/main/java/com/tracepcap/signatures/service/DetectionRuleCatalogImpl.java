package com.tracepcap.signatures.service;

import com.tracepcap.analysis.spi.DetectionRuleCatalog;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class DetectionRuleCatalogImpl implements DetectionRuleCatalog {

  private final JdbcTemplate jdbc;

  @Override
  public Map<String, RuleSummary> rulesInEffect(UUID fileId, UUID networkId) {
    Map<String, RuleSummary> out = new LinkedHashMap<>();
    // Global rules, minus the ones the network switches off.
    String global = "SELECT r.name, r.severity, r.description FROM detection_rules r WHERE r.scope = 'GLOBAL' AND r.enabled";
    org.springframework.jdbc.core.RowCallbackHandler addGlobal =
        rs -> out.put(rs.getString(1), new RuleSummary(rs.getString(1), rs.getString(2), rs.getString(3), "global"));
    if (networkId == null) {
      jdbc.query(global, addGlobal);
    } else {
      jdbc.query(
          global + " AND NOT EXISTS (SELECT 1 FROM rule_suppressions s WHERE s.rule_id = r.id AND s.network_id = ?)",
          addGlobal,
          networkId);
    }
    jdbc.query(
        "SELECT name, severity, description FROM detection_rules WHERE scope = 'CAPTURE' AND enabled AND file_id = ?",
        rs -> {
          out.put(rs.getString(1), new RuleSummary(rs.getString(1), rs.getString(2), rs.getString(3), "capture"));
        },
        fileId);
    if (networkId != null) {
      String scope = networkName(networkId).orElse("network");
      jdbc.query(
          "SELECT name, severity, description FROM detection_rules WHERE scope = 'NETWORK' AND enabled AND network_id = ?",
          rs -> {
            out.put(rs.getString(1), new RuleSummary(rs.getString(1), rs.getString(2), rs.getString(3), scope));
          },
          networkId);
    }
    return out;
  }

  @Override
  public Optional<String> networkName(UUID networkId) {
    if (networkId == null) return Optional.empty();
    List<String> names = jdbc.queryForList("SELECT name FROM networks WHERE id = ?", String.class, networkId);
    return names.stream().findFirst();
  }
}
