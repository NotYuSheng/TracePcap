package com.tracepcap.signatures.service;

import com.tracepcap.analysis.service.PcapParserService.ConversationInfo;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.CustomSignatureStore;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.signatures.dto.RuleSyncStatusDto;
import com.tracepcap.signatures.entity.DetectionRuleEntity;
import com.tracepcap.signatures.repository.DetectionRuleRepository;
import com.tracepcap.signatures.service.RuleSync.Evaluation;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Keeps rule matches in step with the rules (#925 phase 2).
 *
 * <ul>
 *   <li><b>Status:</b> a capture is <i>stale</i> for an enabled rule it hasn't been checked
 *       against at the rule's current version. A payload rule re-checked after retention deleted
 *       the packets is <i>uncheckable</i> at that version: its old matches are dropped, not shown
 *       as if current.
 *   <li><b>Re-apply</b> re-checks one capture's stale rules, in one transaction under the
 *       capture's lock, so it's safe to repeat and never half-applied.
 *   <li><b>Labels</b> ({@code custom_signatures}) are recomputed from the matches and the enabled
 *       rules: at once when a rule is switched off or on, renamed or deleted.
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RuleSyncService {

  private final DetectionRuleRepository ruleRepository;
  private final RuleSync ruleSync;
  private final CustomSignatureService matcher;
  private final ConversationLookup conversationLookup;
  private final CustomSignatureStore labelStore;
  private final FileRepository fileRepository;

  /** The install-wide picture, for the Detection rules tab. */
  @Transactional(readOnly = true)
  public RuleSyncStatusDto overall() {
    List<DetectionRuleEntity> rules = enabledRules();
    Map<UUID, Map<UUID, Evaluation>> evals = ruleSync.evaluationsByFile();
    int stale = 0, uncheckable = 0;
    List<UUID> files = fileRepository.findCompletedIds();
    for (UUID f : files) {
      Map<UUID, Evaluation> e = evals.getOrDefault(f, Map.of());
      if (!staleRules(rules, e).isEmpty()) stale++;
      if (!uncheckableRules(rules, e).isEmpty()) uncheckable++;
    }
    return RuleSyncStatusDto.builder()
        .captures(files.size())
        .staleCaptures(stale)
        .uncheckableCaptures(uncheckable)
        .build();
  }

  /** One capture: which enabled rules it's out of date for, and which couldn't be re-checked. */
  @Transactional(readOnly = true)
  public RuleSyncStatusDto forFile(UUID fileId) {
    List<DetectionRuleEntity> rules = enabledRules();
    Map<UUID, Evaluation> e = ruleSync.evaluationsForFile(fileId);
    boolean completed =
        fileRepository.findById(fileId).map(f -> f.getStatus() == FileEntity.FileStatus.COMPLETED).orElse(false);
    List<String> stale = completed ? staleRules(rules, e).stream().map(DetectionRuleEntity::getName).toList() : List.of();
    List<String> unc = uncheckableRules(rules, e).stream().map(DetectionRuleEntity::getName).toList();
    return RuleSyncStatusDto.builder()
        .captures(1)
        .staleCaptures(stale.isEmpty() ? 0 : 1)
        .uncheckableCaptures(unc.isEmpty() ? 0 : 1)
        .staleRules(stale)
        .uncheckableRules(unc)
        .build();
  }

  /** Captures out of date for at least one enabled rule. */
  @Transactional(readOnly = true)
  public List<UUID> staleFiles() {
    List<DetectionRuleEntity> rules = enabledRules();
    Map<UUID, Map<UUID, Evaluation>> evals = ruleSync.evaluationsByFile();
    List<UUID> out = new ArrayList<>();
    for (UUID f : fileRepository.findCompletedIds()) {
      if (!staleRules(rules, evals.getOrDefault(f, Map.of())).isEmpty()) out.add(f);
    }
    return out;
  }

  /**
   * Re-checks one capture against the enabled rules it's stale for, and rewrites its labels. Runs
   * in its own transaction. Returns how many rules were checked (0 if it was already current or
   * isn't a completed capture).
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public int reapply(UUID fileId) {
    FileEntity file = fileRepository.findById(fileId).orElse(null);
    if (file == null || file.getStatus() != FileEntity.FileStatus.COMPLETED) return 0;
    ruleSync.lockFile(fileId);
    List<DetectionRuleEntity> stale = staleRules(enabledRules(), ruleSync.evaluationsForFile(fileId));
    if (stale.isEmpty()) return 0;

    boolean packetsGone = file.getPacketsPrunedAt() != null;
    List<DetectionRuleEntity> checkable = new ArrayList<>();
    List<DetectionRuleEntity> uncheckable = new ArrayList<>();
    for (DetectionRuleEntity r : stale) {
      (packetsGone && CustomSignatureService.isPayloadRule(r) ? uncheckable : checkable).add(r);
    }
    Map<UUID, List<UUID>> matched =
        checkable.isEmpty() ? Map.of() : matcher.evaluate(conversations(fileId), checkable);
    ruleSync.replaceResults(fileId, checkable, matched, uncheckable);
    labelStore.replaceForFile(fileId, ruleSync.labelsForFile(fileId));
    log.info(
        "Re-applied {} rule(s) to {}: {} checked, {} couldn't be re-checked (packets deleted)",
        stale.size(), fileId, checkable.size(), uncheckable.size());
    return stale.size();
  }

  /**
   * Rewrites the labels of every capture {@code ruleId} matched, after the rule was switched on or
   * off, renamed, or (with the ids gathered before) deleted. Joins the caller's transaction.
   */
  @Transactional(propagation = Propagation.MANDATORY)
  public void refreshLabels(List<UUID> fileIds) {
    for (UUID f : fileIds) {
      ruleSync.lockFile(f);
      labelStore.replaceForFile(f, ruleSync.labelsForFile(f));
    }
  }

  public List<UUID> filesMatchedBy(UUID ruleId) {
    return ruleSync.filesMatchedBy(ruleId);
  }

  // ── helpers ──────────────────────────────────────────────────────────────────

  private List<DetectionRuleEntity> enabledRules() {
    return ruleRepository.findByScopeAndEnabledTrueOrderByNameAsc(DetectionRuleEntity.Scope.GLOBAL);
  }

  static List<DetectionRuleEntity> staleRules(List<DetectionRuleEntity> rules, Map<UUID, Evaluation> evals) {
    List<DetectionRuleEntity> out = new ArrayList<>();
    for (DetectionRuleEntity r : rules) {
      Evaluation e = evals.get(r.getId());
      if (e == null || e.ruleVersion() < r.getVersion()) out.add(r);
    }
    return out;
  }

  static List<DetectionRuleEntity> uncheckableRules(List<DetectionRuleEntity> rules, Map<UUID, Evaluation> evals) {
    List<DetectionRuleEntity> out = new ArrayList<>();
    for (DetectionRuleEntity r : rules) {
      Evaluation e = evals.get(r.getId());
      if (e != null && e.ruleVersion() == r.getVersion() && "UNCHECKABLE".equals(e.result())) out.add(r);
    }
    return out;
  }

  /** The capture's conversations, in the shape the matcher reads. */
  private List<ConversationInfo> conversations(UUID fileId) {
    List<ConversationInfo> out = new ArrayList<>();
    for (ConversationLookup.ConversationFacts f : conversationLookup.conversationFacts(fileId)) {
      ConversationInfo c = new ConversationInfo();
      c.setEntityId(f.id());
      c.setSrcIp(f.flow().srcIp());
      c.setSrcPort(f.flow().srcPort());
      c.setDstIp(f.flow().dstIp());
      c.setDstPort(f.flow().dstPort());
      c.setProtocol(f.flow().protocol());
      c.setHostname(f.tls().hostname());
      c.setJa3Client(f.tls().ja3Client());
      c.setJa3Server(f.tls().ja3Server());
      c.setAppName(f.findings().appName());
      out.add(c);
    }
    return out;
  }
}
