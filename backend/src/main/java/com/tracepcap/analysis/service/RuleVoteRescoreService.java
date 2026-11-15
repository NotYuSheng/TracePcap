package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.spi.ClassificationHint;
import com.tracepcap.analysis.spi.HostClassifier;
import com.tracepcap.analysis.spi.RuleVoteRescorer;
import com.tracepcap.common.adjudication.HumanOverrideEntity;
import com.tracepcap.common.adjudication.HumanOverrideRepository;
import com.tracepcap.common.event.HostClassificationsRescoredEvent;
import com.tracepcap.governance.AuditLogService;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RuleVoteRescoreService implements RuleVoteRescorer {

  /** What re-scoring one host did: its device type before and after. */
  record Rescore(boolean votesChanged, String fromType, String toType) {
    boolean typeChanged() {
      return votesChanged && !java.util.Objects.equals(fromType, toType);
    }
  }

  /** The human-override question for a host's identity (see HostIdentityService). */
  static final String HOST_IDENTITY = "host-identity";

  /** Display names analysts pick for the built-in types, so "IoT Device" matches IOT. */
  private static final Map<String, String> LABELS =
      Map.ofEntries(
          Map.entry("ROUTER", "Router"),
          Map.entry("MOBILE", "Mobile"),
          Map.entry("LAPTOP_DESKTOP", "Laptop / Desktop"),
          Map.entry("SERVER", "Server"),
          Map.entry("IOT", "IoT Device"),
          Map.entry("DNS_SERVER", "DNS Server"),
          Map.entry("WEB_SERVER", "Web Server"),
          Map.entry("API_SERVER", "API Server"),
          Map.entry("UNKNOWN", "Unknown"));

  private final HostClassificationRepository hosts;
  private final HostClassifier classifier;
  private final HumanOverrideRepository overrides;
  private final AuditLogService auditLog;
  private final ApplicationEventPublisher events;

  @Override
  @Transactional(propagation = Propagation.MANDATORY)
  public Outcome rescore(UUID fileId, Map<String, List<ClassificationHint>> votes, String actor) {
    List<Change> changes = new ArrayList<>();
    int stale = 0;
    boolean anyVotesChanged = false;
    for (HostClassificationEntity host : hosts.findByFileId(fileId)) {
      // A failover address's type comes from the protocol, not the vote.
      if (HostIdentityChecks.VIRTUAL_FAILOVER.equals(host.getAddressKind())) continue;
      Map<String, String> before = ruleNames(host.getRuleVotes());
      String fromType = host.getDeviceType();
      var verdict = host.getTypeScores() == null
          ? java.util.Optional.<HostClassifier.Verdict>empty()
          : classifier.rescoreRuleVotes(boardOf(host), votes.getOrDefault(host.getIp(), List.of()));
      if (verdict.isEmpty()) continue;
      apply(host, verdict.get());
      Rescore r = new Rescore(true, fromType, verdict.get().deviceType());
      anyVotesChanged = true;
      if (r.typeChanged()) {
        List<String> rules = changedRules(before, ruleNames(host.getRuleVotes()));
        host.setRescoredAt(LocalDateTime.now());
        host.setRescoredFrom(r.fromType());
        host.setRescoredBy(actor);
        host.setRescoredRules(String.join(", ", rules));
        changes.add(new Change(fileId, host.getIp(), r.fromType(), r.toType(), rules));
        Map<String, Object> was = new LinkedHashMap<>();
        was.put("deviceType", r.fromType());
        Map<String, Object> now = new LinkedHashMap<>();
        now.put("deviceType", r.toType());
        now.put("rules", rules);
        auditLog.record("host-classification.rescore", "host-classification", fileId + "/" + host.getIp(), was, now);
        if (flagLabelIfContradicted(fileId, host.getIp(), r, rules)) stale++;
      }
      hosts.save(host);
    }
    if (!changes.isEmpty()) events.publishEvent(new HostClassificationsRescoredEvent(fileId));
    if (anyVotesChanged) {
      log.info("Re-scored rule votes on {}: {} device type(s) changed, {} label(s) flagged stale", fileId, changes.size(), stale);
    }
    return new Outcome(changes, stale);
  }

  /** A host's stored board, as the classifier reads it. */
  static HostClassifier.Board boardOf(HostClassificationEntity h) {
    List<ClassificationHint> votes = new ArrayList<>();
    if (h.getRuleVotes() != null) {
      for (var r : h.getRuleVotes()) {
        Object w = r.get("weight");
        votes.add(new ClassificationHint(String.valueOf(r.get("rule")), String.valueOf(r.get("deviceType")),
            w instanceof Number n ? n.intValue() : Integer.parseInt(String.valueOf(w))));
      }
    }
    return new HostClassifier.Board(h.getTypeScores(), h.getTypeReasons(), votes);
  }

  /** Stores a board on a host (at analysis, and after re-scoring). */
  static void applyBoard(HostClassificationEntity h, HostClassifier.Board b) {
    h.setTypeScores(b.scores());
    h.setTypeReasons(b.reasons());
    List<Map<String, Object>> rows = new ArrayList<>();
    if (b.ruleVotes() != null) {
      for (ClassificationHint v : b.ruleVotes()) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("rule", v.source());
        row.put("deviceType", v.deviceType());
        row.put("weight", v.weight());
        rows.add(row);
      }
    }
    h.setRuleVotes(rows);
  }

  private static void apply(HostClassificationEntity h, HostClassifier.Verdict v) {
    h.setDeviceType(v.deviceType());
    h.setConfidence(v.confidence());
    h.setWinnerScore(v.winnerScore());
    h.setRunnerUpType(v.runnerUpType());
    h.setRunnerUpScore(v.runnerUpScore());
    h.setWinnerReasons(v.winnerReasons());
    h.setRunnerUpReasons(v.runnerUpReasons());
    applyBoard(h, v.board());
  }

  /**
   * An analyst's label is never changed; it's flagged stale when the evidence's top answer moved
   * to something the label doesn't say.
   */
  private boolean flagLabelIfContradicted(UUID fileId, String ip, Rescore r, List<String> rules) {
    HumanOverrideEntity o = overrides.findByQuestionAndFileIdAndEntityKey(HOST_IDENTITY, fileId, ip).orElse(null);
    if (o == null || labelMatches(o.getLabel(), r.toType())) return false;
    if (o.getStaleSince() == null) o.setStaleSince(LocalDateTime.now());
    List<String> fields = new ArrayList<>(o.getStaleFields() == null ? List.of() : o.getStaleFields());
    fields.add(
        "Re-apply: rule " + String.join(", ", rules) + " changed the evidence's top answer from "
            + label(r.fromType()) + " to " + label(r.toType()));
    o.setStaleFields(fields);
    overrides.save(o);
    return true;
  }

  static boolean labelMatches(String label, String type) {
    if (label == null || type == null) return false;
    return norm(label).equals(norm(type)) || norm(label).equals(norm(LABELS.getOrDefault(type, type)));
  }

  private static String label(String type) {
    return type == null ? "nothing" : LABELS.getOrDefault(type, type);
  }

  private static String norm(String s) {
    return s.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
  }

  /** Rule name → its vote ("deviceType+weight"), for telling which rules changed. */
  private static Map<String, String> ruleNames(List<Map<String, Object>> votes) {
    Map<String, String> out = new LinkedHashMap<>();
    if (votes != null) votes.forEach(v -> out.put(String.valueOf(v.get("rule")), v.get("deviceType") + "+" + v.get("weight")));
    return out;
  }

  /** The rules whose vote was added, removed or changed. */
  private static List<String> changedRules(Map<String, String> before, Map<String, String> after) {
    Set<String> names = new TreeSet<>();
    before.forEach((k, v) -> { if (!v.equals(after.get(k))) names.add(k); });
    after.forEach((k, v) -> { if (!v.equals(before.get(k))) names.add(k); });
    return new ArrayList<>(names);
  }
}
