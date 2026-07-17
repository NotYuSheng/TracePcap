package com.tracepcap.insights.service;

import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.common.stage.Adjudicator;
import com.tracepcap.common.stage.Tier;
import com.tracepcap.analysis.spi.HostClassificationLookup.ClassifiedHost;
import com.tracepcap.insights.entity.HostIdentityEntity;
import com.tracepcap.insights.entity.NodeRoleEntity;
import com.tracepcap.insights.repository.HostIdentityRepository;
import com.tracepcap.insights.repository.NodeRoleRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The host-identity adjudicator (#512 slice 5) — one voice for "what is this host?" (#499).
 *
 * <p>Ranked inputs, per the architecture contract (human annotations first, then machine):
 *
 * <ol>
 *   <li>A human-confirmed node-role label for the IP ({@code confirmedByHuman}, entityType IP) —
 *       basis HUMAN, confidence 100, never contested. The analyst has spoken.
 *   <li>The classification vote's winner — basis MACHINE, at the vote's margin-based confidence.
 *       When the margin is small ({@code confidence < CONTESTED_BELOW}) and a runner-up exists,
 *       the identity is <b>contested</b>: both candidates are listed, and the UI is expected to
 *       render the contest rather than assert the winner (#498).
 * </ol>
 *
 * <p>Re-adjudication fires on analysis completion and on node-role changes (staleness IS
 * re-adjudication). Rows are versioned per run: delete-and-regenerate per file.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class HostIdentityService implements Adjudicator {

  @Override
  public String question() {
    return "host-identity";
  }

  @Override
  public Tier tier() {
    // Weighted votes and a margin threshold — arithmetic, not a language model. The *inputs* are
    // INFERRED (a classifier's guess) and REPORTED (what a host said); the adjudication itself is
    // deterministic, and a human-confirmed label short-circuits it entirely.
    return Tier.DETERMINISTIC;
  }

  @Override
  public void adjudicate(UUID fileId) {
    adjudicateFile(fileId);
  }

  /** Below this margin-based confidence, a surviving runner-up makes the identity contested. */
  static final int CONTESTED_BELOW = 50;

  private final HostClassificationLookup hostClassificationLookup;
  private final NodeRoleRepository nodeRoleRepository;
  private final HostIdentityRepository hostIdentityRepository;

  @Transactional
  public void adjudicateFile(UUID fileId) {
    List<ClassifiedHost> hosts = hostClassificationLookup.classifiedHosts(fileId);
    if (hosts.isEmpty()) return;

    Map<String, NodeRoleEntity> humanByIp = new HashMap<>();
    for (NodeRoleEntity role : nodeRoleRepository.findByFileIdAndConfirmedByHumanTrue(fileId)) {
      if ("IP".equalsIgnoreCase(role.getEntityType()) && role.getRoleLabel() != null) {
        humanByIp.put(role.getEntityKey(), role);
      }
    }

    List<HostIdentityEntity> identities = new ArrayList<>(hosts.size());
    int contestedCount = 0;
    for (ClassifiedHost host : hosts) {
      NodeRoleEntity human = humanByIp.get(host.ip());
      HostIdentityEntity identity =
          human != null ? fromHuman(fileId, host, human) : fromMachine(fileId, host);
      if (identity.isContested()) contestedCount++;
      identities.add(identity);
    }

    hostIdentityRepository.deleteByFileId(fileId);
    hostIdentityRepository.saveAll(identities);
    log.info(
        "Adjudicated {} host identit(ies) for file {} ({} contested, {} human-confirmed)",
        identities.size(),
        fileId,
        contestedCount,
        humanByIp.size());
  }

  private HostIdentityEntity fromHuman(
      UUID fileId, ClassifiedHost host, NodeRoleEntity human) {
    return HostIdentityEntity.builder()
        .fileId(fileId)
        .ip(host.ip())
        .primaryLabel(human.getRoleLabel())
        .basis(HostIdentityEntity.BASIS_HUMAN)
        .confidence(100)
        .contested(false)
        .updatedAt(LocalDateTime.now())
        .build();
  }

  private HostIdentityEntity fromMachine(UUID fileId, ClassifiedHost host) {
    // Invariant: contested ⇒ runnerUpType != null (checked below) and deviceType is non-null by
    // schema, so the Map.of calls in candidates() cannot see nulls.
    boolean contested =
        host.confidence() < CONTESTED_BELOW
            && host.runnerUpType() != null
            && !host.runnerUpType().equals(host.deviceType());
    return HostIdentityEntity.builder()
        .fileId(fileId)
        .ip(host.ip())
        .primaryLabel(host.deviceType())
        .basis(HostIdentityEntity.BASIS_MACHINE)
        .confidence(host.confidence())
        .contested(contested)
        .candidates(contested ? candidates(host) : null)
        .updatedAt(LocalDateTime.now())
        .build();
  }

  private List<Map<String, Object>> candidates(ClassifiedHost host) {
    return List.of(
        Map.of("label", host.deviceType(), "source", "classification", "score",
            host.winnerScore() == null ? 0 : host.winnerScore()),
        Map.of("label", host.runnerUpType(), "source", "classification", "score",
            host.runnerUpScore() == null ? 0 : host.runnerUpScore()));
  }
}
