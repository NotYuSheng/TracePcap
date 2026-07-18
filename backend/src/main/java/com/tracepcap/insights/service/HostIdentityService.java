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
import java.util.LinkedHashMap;
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
    return QUESTION;
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

  /** The adjudicated question this module answers — also the key its human overrides are filed under. */
  static final String QUESTION = "host-identity";

  /** The evidence-axis question keys whose human overrides feed this vote (#499). */
  private static final List<String> AXIS_QUESTIONS =
      List.of("host-hardware", "host-service", "host-behaviour");

  /** Weight a human axis-override contributes to its label in the identity vote — high, but not a
   *  hard override (that is the direct host-identity "I disagree"). */
  private static final int AXIS_OVERRIDE_WEIGHT = 80;

  /** One human override on an evidence axis, tagged with the axis it corrected. */
  private record AxisOverride(String question, String label, String actor) {}

  private static String axisLabel(String question) {
    return switch (question) {
      case "host-hardware" -> "Hardware";
      case "host-service" -> "Ports / Service";
      case "host-behaviour" -> "Behaviour";
      default -> question;
    };
  }

  private final HostClassificationLookup hostClassificationLookup;
  private final NodeRoleRepository nodeRoleRepository;
  private final HostIdentityRepository hostIdentityRepository;
  private final com.tracepcap.common.adjudication.HumanOverrideRepository humanOverrideRepository;
  private final com.tracepcap.common.adjudication.ManualEvidenceRepository manualEvidenceRepository;

  @Transactional
  public void adjudicateFile(UUID fileId) {
    List<ClassifiedHost> hosts = hostClassificationLookup.classifiedHosts(fileId);
    if (hosts.isEmpty()) return;

    // A generic human override ("I disagree, it's X") ranks above everything — the most direct
    // statement of identity there is. Keyed by this adjudicator's own question().
    Map<String, com.tracepcap.common.adjudication.HumanOverrideEntity> overrideByIp = new HashMap<>();
    for (com.tracepcap.common.adjudication.HumanOverrideEntity o :
        humanOverrideRepository.findByQuestionAndFileId(QUESTION, fileId)) {
      overrideByIp.put(o.getEntityKey(), o);
    }

    Map<String, NodeRoleEntity> humanByIp = new HashMap<>();
    for (NodeRoleEntity role : nodeRoleRepository.findByFileIdAndConfirmedByHumanTrue(fileId)) {
      if ("IP".equalsIgnoreCase(role.getEntityType()) && role.getRoleLabel() != null) {
        humanByIp.put(role.getEntityKey(), role);
      }
    }

    // Analyst-appended evidence, grouped by IP — folded into the machine vote below (not a decision).
    Map<String, List<com.tracepcap.common.adjudication.ManualEvidenceEntity>> evidenceByIp =
        new HashMap<>();
    for (com.tracepcap.common.adjudication.ManualEvidenceEntity e :
        manualEvidenceRepository.findByQuestionAndFileId(QUESTION, fileId)) {
      evidenceByIp.computeIfAbsent(e.getEntityKey(), k -> new ArrayList<>()).add(e);
    }

    // Human overrides on the *evidence axes* (host-hardware / host-service / host-behaviour, #499):
    // a person correcting an axis is a strong statement, so it is folded into the identity vote as
    // heavily-weighted evidence — it cascades to the verdict without hard-overriding it (that is what
    // the direct host-identity "I disagree" is for). Grouped by IP, tagged with the axis it came from.
    Map<String, List<AxisOverride>> axisOverridesByIp = new HashMap<>();
    for (String axisQuestion : AXIS_QUESTIONS) {
      for (com.tracepcap.common.adjudication.HumanOverrideEntity o :
          humanOverrideRepository.findByQuestionAndFileId(axisQuestion, fileId)) {
        axisOverridesByIp
            .computeIfAbsent(o.getEntityKey(), k -> new ArrayList<>())
            .add(new AxisOverride(axisQuestion, o.getLabel(), o.getActor()));
      }
    }

    List<HostIdentityEntity> identities = new ArrayList<>(hosts.size());
    int contestedCount = 0;
    for (ClassifiedHost host : hosts) {
      com.tracepcap.common.adjudication.HumanOverrideEntity override = overrideByIp.get(host.ip());
      NodeRoleEntity human = humanByIp.get(host.ip());
      HostIdentityEntity identity;
      if (override != null) {
        identity = fromOverride(fileId, host, override);
      } else if (human != null) {
        identity = fromHuman(fileId, host, human);
      } else {
        identity =
            fromMachine(
                fileId,
                host,
                evidenceByIp.getOrDefault(host.ip(), List.of()),
                axisOverridesByIp.getOrDefault(host.ip(), List.of()));
      }
      if (identity.isContested()) contestedCount++;
      identities.add(identity);
    }

    hostIdentityRepository.deleteByFileId(fileId);
    hostIdentityRepository.saveAll(identities);
    log.info(
        "Adjudicated {} host identit(ies) for file {} ({} contested, {} overridden, {} human-confirmed)",
        identities.size(),
        fileId,
        contestedCount,
        overrideByIp.size(),
        humanByIp.size());
  }

  private HostIdentityEntity fromOverride(
      UUID fileId, ClassifiedHost host, com.tracepcap.common.adjudication.HumanOverrideEntity override) {
    return HostIdentityEntity.builder()
        .fileId(fileId)
        .ip(host.ip())
        .primaryLabel(override.getLabel())
        .basis(HostIdentityEntity.BASIS_HUMAN)
        .confidence(100)
        .contested(false)
        .updatedAt(LocalDateTime.now())
        .build();
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

  private HostIdentityEntity fromMachine(
      UUID fileId,
      ClassifiedHost host,
      List<com.tracepcap.common.adjudication.ManualEvidenceEntity> evidence,
      List<AxisOverride> axisOverrides) {
    // No analyst evidence AND no axis override: keep the classifier's own confidence, fast path.
    if (evidence.isEmpty() && axisOverrides.isEmpty()) {
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
          .candidates(machineCandidates(host))
          .updatedAt(LocalDateTime.now())
          .build();
    }

    // Analyst evidence and/or a human axis-override present: fold everything into the vote as
    // weighted signals. Start from the two machine candidates' scores, add each signal to its label,
    // then re-decide. These inform — they never hard-override (that is the direct host-identity
    // "I disagree").
    Map<String, Integer> scores = new LinkedHashMap<>();
    Map<String, List<String>> reasons = new LinkedHashMap<>();
    accumulate(scores, reasons, host.deviceType(), score(host.winnerScore()), host.winnerReasons());
    if (host.runnerUpType() != null) {
      accumulate(
          scores, reasons, host.runnerUpType(), score(host.runnerUpScore()), host.runnerUpReasons());
    }
    // A human axis-override is a strong statement — weight it heavily so it usually wins, yet still
    // shows in the candidate vote rather than silently replacing the machine (#499).
    for (AxisOverride ao : axisOverrides) {
      accumulate(
          scores,
          reasons,
          ao.label(),
          AXIS_OVERRIDE_WEIGHT,
          List.of(
              "analyst ("
                  + (ao.actor() == null || ao.actor().isBlank() ? "an analyst" : ao.actor())
                  + ") corrected "
                  + axisLabel(ao.question())
                  + " to "
                  + ao.label()
                  + " (+"
                  + AXIS_OVERRIDE_WEIGHT
                  + ")"));
    }
    for (com.tracepcap.common.adjudication.ManualEvidenceEntity e : evidence) {
      accumulate(
          scores,
          reasons,
          e.getLabel(),
          e.getWeight(),
          List.of("analyst (" + e.getActor() + "): " + e.getReason() + " (+" + e.getWeight() + ")"));
    }

    List<Map.Entry<String, Integer>> ranked =
        scores.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .toList();
    String winner = ranked.get(0).getKey();
    int best = ranked.get(0).getValue();
    int second = ranked.size() > 1 ? ranked.get(1).getValue() : 0;
    int confidence = Math.min(100, (int) Math.round((best - second) * 100.0 / MARGIN_FOR_FULL));
    boolean contested = confidence < CONTESTED_BELOW && ranked.size() > 1;

    return HostIdentityEntity.builder()
        .fileId(fileId)
        .ip(host.ip())
        .primaryLabel(winner)
        .basis(HostIdentityEntity.BASIS_MACHINE)
        .confidence(confidence)
        .contested(contested)
        .candidates(votedCandidates(ranked, reasons))
        .updatedAt(LocalDateTime.now())
        .build();
  }

  /** Score margin (winner − runner-up) mapping to 100% confidence; mirrors the classifier's own. */
  private static final int MARGIN_FOR_FULL = 60;

  private static int score(Integer s) {
    return s == null ? 0 : s;
  }

  private void accumulate(
      Map<String, Integer> scores,
      Map<String, List<String>> reasons,
      String label,
      int weight,
      List<String> why) {
    scores.merge(label, weight, Integer::sum);
    reasons.computeIfAbsent(label, k -> new ArrayList<>()).addAll(why);
  }

  /**
   * The machine candidates, with their classification reasons — used when no evidence exists. The
   * winner always appears so the verdict's own reasoning is shown; the runner-up is only added when
   * one exists (an uncontested verdict may have none), which also keeps its null label out of the
   * NPE-throwing {@code Map.of} in {@link #candidate}.
   */
  private List<Map<String, Object>> machineCandidates(ClassifiedHost host) {
    List<Map<String, Object>> out = new ArrayList<>(2);
    out.add(candidate(host.deviceType(), score(host.winnerScore()), host.winnerReasons()));
    if (host.runnerUpType() != null && !host.runnerUpType().equals(host.deviceType())) {
      out.add(candidate(host.runnerUpType(), score(host.runnerUpScore()), host.runnerUpReasons()));
    }
    return out;
  }

  /** Candidates after folding evidence: every voted-for label, ranked, with its combined reasons. */
  private List<Map<String, Object>> votedCandidates(
      List<Map.Entry<String, Integer>> ranked, Map<String, List<String>> reasons) {
    List<Map<String, Object>> out = new ArrayList<>(ranked.size());
    for (Map.Entry<String, Integer> e : ranked) {
      out.add(candidate(e.getKey(), e.getValue(), reasons.getOrDefault(e.getKey(), List.of())));
    }
    return out;
  }

  private Map<String, Object> candidate(String label, int score, List<String> reasons) {
    return Map.of("label", label, "source", "classification", "score", score, "reasons", reasons);
  }
}
