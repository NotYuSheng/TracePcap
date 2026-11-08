package com.tracepcap.signatures.service;

import com.tracepcap.signatures.entity.DetectionRuleEntity;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The rule-sync tables (#925 phase 2, V52): which conversations each rule matched, and which rule
 * version each capture was last checked against. Every write runs inside the caller's
 * transaction, under the capture's lock, so one capture's results change all at once or not at
 * all.
 */
@Component
@RequiredArgsConstructor
public class RuleSync {

  /** A capture's last check against one rule. */
  public record Evaluation(UUID ruleId, UUID fileId, int ruleVersion, String result, int matchCount) {}

  /** Distinguishes these advisory locks from any other use of pg_advisory_xact_lock. */
  private static final int LOCK_SPACE = 925;

  private final JdbcTemplate jdbc;

  /** Serialises rule results per capture: analysis and Re-apply take this before writing. */
  @Transactional(propagation = Propagation.MANDATORY)
  public void lockFile(UUID fileId) {
    jdbc.queryForObject("SELECT pg_advisory_xact_lock(?, hashtext(?))", Object.class, LOCK_SPACE, fileId.toString());
  }

  /**
   * Replaces the results of {@code checked} and {@code uncheckable} rules on one capture: their old
   * matches go, {@code matches} (rule id → conversation ids) come in, and each rule's evaluation
   * is set to its current version. Rules in neither list are left alone.
   */
  @Transactional(propagation = Propagation.MANDATORY)
  public void replaceResults(
      UUID fileId,
      List<DetectionRuleEntity> checked,
      Map<UUID, List<UUID>> matches,
      List<DetectionRuleEntity> uncheckable) {
    List<DetectionRuleEntity> all = new ArrayList<>(checked);
    all.addAll(uncheckable);
    if (all.isEmpty()) return;
    UUID[] ids = all.stream().map(DetectionRuleEntity::getId).toArray(UUID[]::new);
    jdbc.update(
        con -> {
          PreparedStatement ps =
              con.prepareStatement("DELETE FROM rule_matches WHERE file_id = ? AND rule_id = ANY (?)");
          ps.setObject(1, fileId);
          ps.setArray(2, con.createArrayOf("uuid", ids));
          return ps;
        });

    List<Object[]> rows = new ArrayList<>();
    for (DetectionRuleEntity r : checked) {
      for (UUID conv : matches.getOrDefault(r.getId(), List.of())) rows.add(new Object[] {r.getId(), fileId, conv});
    }
    if (!rows.isEmpty()) {
      jdbc.batchUpdate(
          "INSERT INTO rule_matches (rule_id, file_id, conversation_id) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
          rows);
    }

    Timestamp now = Timestamp.valueOf(LocalDateTime.now());
    List<Object[]> evals = new ArrayList<>();
    for (DetectionRuleEntity r : checked) {
      evals.add(new Object[] {r.getId(), fileId, r.getVersion(), "CHECKED", matches.getOrDefault(r.getId(), List.of()).size(), now});
    }
    for (DetectionRuleEntity r : uncheckable) {
      evals.add(new Object[] {r.getId(), fileId, r.getVersion(), "UNCHECKABLE", 0, now});
    }
    jdbc.batchUpdate(
        "INSERT INTO rule_evaluations (rule_id, file_id, rule_version, result, match_count, evaluated_at)"
            + " VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (rule_id, file_id) DO UPDATE SET"
            + " rule_version = EXCLUDED.rule_version, result = EXCLUDED.result,"
            + " match_count = EXCLUDED.match_count, evaluated_at = EXCLUDED.evaluated_at",
        evals);
  }

  /**
   * What each conversation in a capture should be labelled with: the names of the enabled global
   * rules that matched it, by name. This is the read model's source (custom_signatures).
   */
  public Map<UUID, List<String>> labelsForFile(UUID fileId) {
    Map<UUID, List<String>> out = new LinkedHashMap<>();
    jdbc.query(
        "SELECT m.conversation_id, r.name FROM rule_matches m JOIN detection_rules r ON r.id = m.rule_id"
            + " WHERE m.file_id = ? AND r.enabled AND r.scope = 'GLOBAL' ORDER BY m.conversation_id, r.name",
        rs -> {
          out.computeIfAbsent(rs.getObject(1, UUID.class), k -> new ArrayList<>()).add(rs.getString(2));
        },
        fileId);
    return out;
  }

  /** Captures where {@code ruleId} has matches. */
  public List<UUID> filesMatchedBy(UUID ruleId) {
    return jdbc.queryForList("SELECT DISTINCT file_id FROM rule_matches WHERE rule_id = ?", UUID.class, ruleId);
  }

  /** Every evaluation, grouped by capture then rule. */
  public Map<UUID, Map<UUID, Evaluation>> evaluationsByFile() {
    Map<UUID, Map<UUID, Evaluation>> out = new HashMap<>();
    jdbc.query(
        "SELECT rule_id, file_id, rule_version, result, match_count FROM rule_evaluations",
        rs -> {
          Evaluation e =
              new Evaluation(
                  rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getInt(3), rs.getString(4), rs.getInt(5));
          out.computeIfAbsent(e.fileId(), k -> new HashMap<>()).put(e.ruleId(), e);
        });
    return out;
  }

  /** One capture's evaluations, by rule. */
  public Map<UUID, Evaluation> evaluationsForFile(UUID fileId) {
    Map<UUID, Evaluation> out = new HashMap<>();
    jdbc.query(
        "SELECT rule_id, file_id, rule_version, result, match_count FROM rule_evaluations WHERE file_id = ?",
        rs -> {
          Evaluation e =
              new Evaluation(
                  rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getInt(3), rs.getString(4), rs.getInt(5));
          out.put(e.ruleId(), e);
        },
        fileId);
    return out;
  }
}
