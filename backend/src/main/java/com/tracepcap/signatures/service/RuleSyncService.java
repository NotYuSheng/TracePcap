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
  private final com.tracepcap.monitor.repository.NetworkSnapshotRepository snapshotRepository;

  /** The install-wide picture, for the Detection rules tab. */
  @Transactional(readOnly = true)
  public RuleSyncStatusDto overall() {
    Map<UUID, Map<UUID, Evaluation>> evals = ruleSync.evaluationsByFile();
    RulesByFile rules = rulesByFile();
    int stale = 0, uncheckable = 0;
    List<UUID> files = fileRepository.findCompletedIds();
    for (UUID f : files) {
      Map<UUID, Evaluation> e = evals.getOrDefault(f, Map.of());
      List<DetectionRuleEntity> forFile = rules.forFile(f);
      if (!staleRules(forFile, e).isEmpty()) stale++;
      if (!uncheckableRules(forFile, e).isEmpty()) uncheckable++;
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
    List<DetectionRuleEntity> rules = enabledRules(fileId);
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
    RulesByFile rules = rulesByFile();
    Map<UUID, Map<UUID, Evaluation>> evals = ruleSync.evaluationsByFile();
    List<UUID> out = new ArrayList<>();
    for (UUID f : fileRepository.findCompletedIds()) {
      if (!staleRules(rules.forFile(f), evals.getOrDefault(f, Map.of())).isEmpty()) out.add(f);
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
    List<DetectionRuleEntity> stale = staleRules(enabledRules(fileId), ruleSync.evaluationsForFile(fileId));
    if (stale.isEmpty()) return 0;
    check(file, stale);
    return stale.size();
  }

  /**
   * Checks the given rules against one capture now, in the caller's transaction: used when a
   * capture rule is saved, and for a promoted copy on its source capture (#925 phase 3).
   */
  @Transactional(propagation = Propagation.MANDATORY)
  public void checkNow(UUID fileId, List<DetectionRuleEntity> rules) {
    FileEntity file = fileRepository.findById(fileId).orElse(null);
    if (file == null || file.getStatus() != FileEntity.FileStatus.COMPLETED || rules.isEmpty()) return;
    ruleSync.lockFile(fileId);
    check(file, rules);
  }

  private void check(FileEntity file, List<DetectionRuleEntity> stale) {
    UUID fileId = file.getId();
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
        "Checked {} rule(s) on {}: {} checked, {} couldn't be re-checked (packets deleted)",
        stale.size(), fileId, checkable.size(), uncheckable.size());
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

  /** The enabled rules that apply to one capture: global, its own, and its networks' (#925). */
  private List<DetectionRuleEntity> enabledRules(UUID fileId) {
    List<DetectionRuleEntity> out =
        new ArrayList<>(ruleRepository.findByScopeAndEnabledTrueOrderByNameAsc(DetectionRuleEntity.Scope.GLOBAL));
    out.addAll(ruleRepository.findByScopeAndFileIdAndEnabledTrueOrderByNameAsc(DetectionRuleEntity.Scope.CAPTURE, fileId));
    for (var snap : snapshotRepository.findByFileId(fileId)) {
      out.addAll(
          ruleRepository.findByScopeAndNetworkIdAndEnabledTrueOrderByNameAsc(
              DetectionRuleEntity.Scope.NETWORK, snap.getNetwork().getId()));
    }
    return out;
  }

  /**
   * A capture joined a network: check the network's enabled rules on it now (#925 phase 3), in
   * its own transaction. Called after the membership change committed.
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void onJoinedNetwork(UUID networkId, UUID fileId) {
    FileEntity file = fileRepository.findById(fileId).orElse(null);
    if (file == null || file.getStatus() != FileEntity.FileStatus.COMPLETED) return;
    List<DetectionRuleEntity> rules =
        ruleRepository.findByScopeAndNetworkIdAndEnabledTrueOrderByNameAsc(DetectionRuleEntity.Scope.NETWORK, networkId);
    if (rules.isEmpty()) return;
    ruleSync.lockFile(fileId);
    check(file, rules);
  }

  /**
   * Viewing a capture in a network it isn't part of (#925 phase 3): nothing checks that network's
   * rules on it otherwise, so they're checked on demand, in their own transaction, and only those
   * not yet checked at their current version. Members keep the usual model (out of date until
   * re-applied).
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void ensureCheckedForViewing(UUID networkId, UUID fileId) {
    if (snapshotRepository.findByNetworkIdAndFileId(networkId, fileId).isPresent()) return;
    List<DetectionRuleEntity> rules =
        ruleRepository.findByScopeAndNetworkIdAndEnabledTrueOrderByNameAsc(DetectionRuleEntity.Scope.NETWORK, networkId);
    if (rules.isEmpty() || staleRules(rules, ruleSync.evaluationsForFile(fileId)).isEmpty()) return;
    FileEntity file = fileRepository.findById(fileId).orElse(null);
    if (file == null || file.getStatus() != FileEntity.FileStatus.COMPLETED) return;
    ruleSync.lockFile(fileId);
    List<DetectionRuleEntity> stale = staleRules(rules, ruleSync.evaluationsForFile(fileId)); // under the lock
    if (!stale.isEmpty()) check(file, stale);
  }

  /** A capture left a network: drop that network's rule results for it (#925 phase 3). */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void onLeftNetwork(UUID networkId, UUID fileId) {
    if (snapshotRepository.findByNetworkIdAndFileId(networkId, fileId).isPresent()) return; // still in it
    List<UUID> ruleIds =
        ruleRepository.findByScopeAndNetworkId(DetectionRuleEntity.Scope.NETWORK, networkId).stream()
            .map(DetectionRuleEntity::getId)
            .toList();
    if (ruleIds.isEmpty()) return;
    ruleSync.lockFile(fileId);
    ruleSync.removeResults(fileId, ruleIds);
  }

  /** The enabled global rules, and each capture's own, loaded once for an install-wide pass. */
  private record RulesByFile(List<DetectionRuleEntity> global, Map<UUID, List<DetectionRuleEntity>> capture) {
    List<DetectionRuleEntity> forFile(UUID fileId) {
      List<DetectionRuleEntity> own = capture.get(fileId);
      if (own == null) return global;
      List<DetectionRuleEntity> out = new ArrayList<>(global);
      out.addAll(own);
      return out;
    }
  }

  private RulesByFile rulesByFile() {
    // Each capture's own rules, plus the rules of every network it's in (#925 phase 3).
    Map<UUID, List<DetectionRuleEntity>> capture = new java.util.HashMap<>();
    for (DetectionRuleEntity r : ruleRepository.findByScopeAndEnabledTrue(DetectionRuleEntity.Scope.CAPTURE)) {
      capture.computeIfAbsent(r.getFileId(), k -> new ArrayList<>()).add(r);
    }
    Map<UUID, List<DetectionRuleEntity>> byNetwork = new java.util.HashMap<>();
    for (DetectionRuleEntity r : ruleRepository.findByScopeAndEnabledTrue(DetectionRuleEntity.Scope.NETWORK)) {
      byNetwork.computeIfAbsent(r.getNetworkId(), k -> new ArrayList<>()).add(r);
    }
    if (!byNetwork.isEmpty()) {
      for (Object[] m : snapshotRepository.findAllMemberships()) {
        List<DetectionRuleEntity> rules = byNetwork.get((UUID) m[0]);
        if (rules != null) capture.computeIfAbsent((UUID) m[1], k -> new ArrayList<>()).addAll(rules);
      }
    }
    return new RulesByFile(
        ruleRepository.findByScopeAndEnabledTrueOrderByNameAsc(DetectionRuleEntity.Scope.GLOBAL), capture);
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
