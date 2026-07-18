package com.tracepcap.insights.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.ClassifiedHost;
import com.tracepcap.insights.entity.HostIdentityEntity;
import com.tracepcap.insights.entity.NodeRoleEntity;
import com.tracepcap.insights.repository.HostIdentityRepository;
import com.tracepcap.insights.repository.NodeRoleRepository;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * The adjudication contract (#512 slice 5): human-confirmed labels rank first and are never
 * contested; machine winners carry the vote's confidence; a small margin with a surviving
 * runner-up is an explicit contest, not a quiet assertion (#499/#498).
 */
class HostIdentityServiceTest {

  private final UUID fileId = UUID.randomUUID();
  private final HostClassificationLookup lookup = mock(HostClassificationLookup.class);
  private final NodeRoleRepository roleRepo = mock(NodeRoleRepository.class);
  private final HostIdentityRepository identityRepo = mock(HostIdentityRepository.class);
  private final com.tracepcap.common.adjudication.HumanOverrideRepository overrideRepo =
      mock(com.tracepcap.common.adjudication.HumanOverrideRepository.class);
  private final com.tracepcap.common.adjudication.ManualEvidenceRepository evidenceRepo =
      mock(com.tracepcap.common.adjudication.ManualEvidenceRepository.class);
  private final HostIdentityService service =
      new HostIdentityService(lookup, roleRepo, identityRepo, overrideRepo, evidenceRepo);

  /** A classified host with empty reason lists — for tests not asserting on the reasons trail. */
  private static ClassifiedHost host(
      String ip, String type, int confidence, Integer winnerScore, String runnerUp, Integer runnerUpScore) {
    return new ClassifiedHost(
        ip, type, confidence, winnerScore, runnerUp, runnerUpScore, List.of(), List.of());
  }

  private List<HostIdentityEntity> adjudicated() {
    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<HostIdentityEntity>> captor = ArgumentCaptor.forClass((Class) List.class);
    verify(identityRepo).saveAll(captor.capture());
    return captor.getValue();
  }

  @Test
  void humanConfirmedLabel_ranksFirst_neverContested() {
    when(lookup.classifiedHosts(fileId))
        .thenReturn(List.of(host("10.0.0.1", "WEB_SERVER", 20, 90, "IOT", 70)));
    NodeRoleEntity human = new NodeRoleEntity();
    human.setEntityType("IP");
    human.setEntityKey("10.0.0.1");
    human.setRoleLabel("Core Router");
    when(roleRepo.findByFileIdAndConfirmedByHumanTrue(fileId)).thenReturn(List.of(human));

    service.adjudicateFile(fileId);

    HostIdentityEntity id = adjudicated().get(0);
    assertThat(id.getPrimaryLabel()).isEqualTo("Core Router");
    assertThat(id.getBasis()).isEqualTo(HostIdentityEntity.BASIS_HUMAN);
    assertThat(id.getConfidence()).isEqualTo(100);
    assertThat(id.isContested()).isFalse();
  }

  @Test
  void humanOverride_ranksAboveEverything_neverContested() {
    // Even a strong, uncontested machine winner is replaced by an explicit human override.
    when(lookup.classifiedHosts(fileId))
        .thenReturn(List.of(host("10.0.0.9", "IOT", 90, 200, "SERVER", 30)));
    when(roleRepo.findByFileIdAndConfirmedByHumanTrue(any())).thenReturn(List.of());
    com.tracepcap.common.adjudication.HumanOverrideEntity override =
        com.tracepcap.common.adjudication.HumanOverrideEntity.builder()
            .question("host-identity")
            .fileId(fileId)
            .entityKey("10.0.0.9")
            .label("SCADA Historian")
            .actor("alice")
            .build();
    when(overrideRepo.findByQuestionAndFileId("host-identity", fileId))
        .thenReturn(List.of(override));

    service.adjudicateFile(fileId);

    HostIdentityEntity id = adjudicated().get(0);
    assertThat(id.getPrimaryLabel()).isEqualTo("SCADA Historian");
    assertThat(id.getBasis()).isEqualTo(HostIdentityEntity.BASIS_HUMAN);
    assertThat(id.getConfidence()).isEqualTo(100);
    assertThat(id.isContested()).isFalse();
  }

  @Test
  void lowMarginWithRunnerUp_isContested_withBothCandidatesListed() {
    when(lookup.classifiedHosts(fileId))
        .thenReturn(
            List.of(
                new ClassifiedHost(
                    "10.0.0.2", "WEB_SERVER", 30, 100, "IOT", 70,
                    List.of("listens on 80/tcp (+60)", "nDPI: HTTP (+40)"),
                    List.of("low traffic volume (+40)", "few peers (+30)"))));
    when(roleRepo.findByFileIdAndConfirmedByHumanTrue(any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    HostIdentityEntity id = adjudicated().get(0);
    assertThat(id.isContested()).isTrue();
    assertThat(id.getBasis()).isEqualTo(HostIdentityEntity.BASIS_MACHINE);
    assertThat(id.getCandidates()).hasSize(2);
    assertThat(id.getCandidates().get(0)).containsEntry("label", "WEB_SERVER");
    assertThat(id.getCandidates().get(1)).containsEntry("label", "IOT");
    // Explainability: each candidate carries the reasons that voted for it, in order.
    assertThat(id.getCandidates().get(0).get("reasons"))
        .isEqualTo(List.of("listens on 80/tcp (+60)", "nDPI: HTTP (+40)"));
    assertThat(id.getCandidates().get(1).get("reasons"))
        .isEqualTo(List.of("low traffic volume (+40)", "few peers (+30)"));
  }

  @Test
  void manualEvidence_foldsIntoVote_canTipWinner_andShowsInReasons() {
    // Machine: IOT 200 vs SERVER 30. Analyst adds strong SERVER evidence (clamped to 100), so the
    // combined vote is IOT 200 vs SERVER 130 — IOT still wins, but the evidence is now in the trail.
    when(lookup.classifiedHosts(fileId))
        .thenReturn(
            List.of(
                new ClassifiedHost(
                    "10.0.0.7", "IOT", 80, 200, "SERVER", 30,
                    List.of("MAC OUI is Espressif (+40)"),
                    List.of("received on 443 (+30)"))));
    when(roleRepo.findByFileIdAndConfirmedByHumanTrue(any())).thenReturn(List.of());
    com.tracepcap.common.adjudication.ManualEvidenceEntity ev =
        com.tracepcap.common.adjudication.ManualEvidenceEntity.builder()
            .question("host-identity")
            .fileId(fileId)
            .entityKey("10.0.0.7")
            .label("SERVER")
            .weight(100)
            .reason("runs sshd, confirmed via console")
            .actor("bob")
            .build();
    when(evidenceRepo.findByQuestionAndFileId("host-identity", fileId)).thenReturn(List.of(ev));

    service.adjudicateFile(fileId);

    HostIdentityEntity id = adjudicated().get(0);
    assertThat(id.getPrimaryLabel()).isEqualTo("IOT"); // 200 still beats 30+100
    assertThat(id.getBasis()).isEqualTo(HostIdentityEntity.BASIS_MACHINE);
    // The SERVER candidate now carries the analyst's evidence in its reasons, attributed.
    Map<String, Object> serverCandidate =
        id.getCandidates().stream()
            .filter(c -> "SERVER".equals(c.get("label")))
            .findFirst()
            .orElseThrow();
    assertThat(serverCandidate).containsEntry("score", 130);
    @SuppressWarnings("unchecked")
    List<String> reasons = (List<String>) serverCandidate.get("reasons");
    assertThat(reasons).anyMatch(r -> r.contains("analyst (bob)") && r.contains("runs sshd"));
  }

  @Test
  void highConfidenceWalkover_isNotContested() {
    when(lookup.classifiedHosts(fileId))
        .thenReturn(List.of(host("10.0.0.3", "DNS_SERVER", 100, 1040, "ROUTER", 40)));
    when(roleRepo.findByFileIdAndConfirmedByHumanTrue(any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    HostIdentityEntity id = adjudicated().get(0);
    assertThat(id.isContested()).isFalse();
    assertThat(id.getPrimaryLabel()).isEqualTo("DNS_SERVER");
    // Candidates are now always surfaced (even uncontested) so the machine's "Why" is always shown
    // (#499); the winner leads. Previously this was null on an uncontested walkover.
    assertThat(id.getCandidates()).isNotNull();
    assertThat(id.getCandidates().get(0)).containsEntry("label", "DNS_SERVER");
  }

  @Test
  void lowConfidenceButNoRunnerUp_isUncertainNotContested() {
    // Contested means competing answers; a lone weak candidate is just low confidence.
    when(lookup.classifiedHosts(fileId))
        .thenReturn(List.of(host("10.0.0.4", "UNKNOWN", 10, null, null, null)));
    when(roleRepo.findByFileIdAndConfirmedByHumanTrue(any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    assertThat(adjudicated().get(0).isContested()).isFalse();
  }

  @Test
  void reAdjudication_replacesRows() {
    when(lookup.classifiedHosts(fileId))
        .thenReturn(List.of(host("10.0.0.5", "SERVER", 80, 120, null, null)));
    when(roleRepo.findByFileIdAndConfirmedByHumanTrue(any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    verify(identityRepo).deleteByFileId(fileId);
  }
}
