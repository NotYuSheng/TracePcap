package com.tracepcap.insights.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.ClassifiedHost;
import com.tracepcap.insights.entity.HostIdentityEntity;
import com.tracepcap.insights.entity.NodeRoleEntity;
import com.tracepcap.insights.repository.HostIdentityRepository;
import com.tracepcap.insights.repository.NodeRoleRepository;
import java.util.List;
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
  private final HostIdentityService service =
      new HostIdentityService(lookup, roleRepo, identityRepo, new ObjectMapper());

  private List<HostIdentityEntity> adjudicated() {
    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<HostIdentityEntity>> captor = ArgumentCaptor.forClass((Class) List.class);
    verify(identityRepo).saveAll(captor.capture());
    return captor.getValue();
  }

  @Test
  void humanConfirmedLabel_ranksFirst_neverContested() {
    when(lookup.classifiedHosts(fileId))
        .thenReturn(List.of(new ClassifiedHost("10.0.0.1", "WEB_SERVER", 20, 90, "IOT", 70)));
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
  void lowMarginWithRunnerUp_isContested_withBothCandidatesListed() {
    when(lookup.classifiedHosts(fileId))
        .thenReturn(List.of(new ClassifiedHost("10.0.0.2", "WEB_SERVER", 30, 100, "IOT", 70)));
    when(roleRepo.findByFileIdAndConfirmedByHumanTrue(any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    HostIdentityEntity id = adjudicated().get(0);
    assertThat(id.isContested()).isTrue();
    assertThat(id.getBasis()).isEqualTo(HostIdentityEntity.BASIS_MACHINE);
    assertThat(id.getCandidates()).contains("WEB_SERVER").contains("IOT");
  }

  @Test
  void highConfidenceWalkover_isNotContested() {
    when(lookup.classifiedHosts(fileId))
        .thenReturn(List.of(new ClassifiedHost("10.0.0.3", "DNS_SERVER", 100, 1040, "ROUTER", 40)));
    when(roleRepo.findByFileIdAndConfirmedByHumanTrue(any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    HostIdentityEntity id = adjudicated().get(0);
    assertThat(id.isContested()).isFalse();
    assertThat(id.getPrimaryLabel()).isEqualTo("DNS_SERVER");
    assertThat(id.getCandidates()).isNull();
  }

  @Test
  void lowConfidenceButNoRunnerUp_isUncertainNotContested() {
    // Contested means competing answers; a lone weak candidate is just low confidence.
    when(lookup.classifiedHosts(fileId))
        .thenReturn(List.of(new ClassifiedHost("10.0.0.4", "UNKNOWN", 10, null, null, null)));
    when(roleRepo.findByFileIdAndConfirmedByHumanTrue(any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    assertThat(adjudicated().get(0).isContested()).isFalse();
  }

  @Test
  void reAdjudication_replacesRows() {
    when(lookup.classifiedHosts(fileId))
        .thenReturn(List.of(new ClassifiedHost("10.0.0.5", "SERVER", 80, 120, null, null)));
    when(roleRepo.findByFileIdAndConfirmedByHumanTrue(any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    verify(identityRepo).deleteByFileId(fileId);
  }
}
