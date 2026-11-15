package com.tracepcap.insights.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.insights.dto.HostIdentityDto;
import com.tracepcap.insights.service.HostIdentityEvidenceService;
import com.tracepcap.insights.service.HostIdentityService;
import com.tracepcap.insights.service.NodeRoleService;
import com.tracepcap.insights.entity.HostIdentityEntity;
import com.tracepcap.insights.repository.HostIdentityRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** {@code GET /files/{id}/host-identities}, file-wide and scoped to given IPs (#576). */
class HostIdentitiesControllerTest {

  private final UUID fileId = UUID.randomUUID();
  private final HostIdentityRepository repo = mock(HostIdentityRepository.class);
  private final HostIdentityService adjudicator = mock(HostIdentityService.class);
  private final HostIdentitiesController controller =
      new HostIdentitiesController(
          repo, adjudicator, mock(HostIdentityEvidenceService.class), mock(NodeRoleService.class));

  private HostIdentityEntity identity(String ip) {
    return HostIdentityEntity.builder().fileId(fileId).ip(ip).primaryLabel("ROUTER").build();
  }

  @Test
  void withIps_fetchesOnlyThoseHosts_neverTheWholeFile() {
    when(repo.existsByFileId(fileId)).thenReturn(true);
    when(repo.findByFileIdAndIpIn(fileId, List.of("10.0.0.1", "10.0.0.2")))
        .thenReturn(List.of(identity("10.0.0.1")));

    List<HostIdentityDto> body = controller.getHostIdentities(fileId, List.of(" 10.0.0.1", "10.0.0.2 ", "")).getBody();

    // Trimmed, blanks dropped; an IP with no identity is simply absent.
    assertThat(body).extracting(HostIdentityDto::getIp).containsExactly("10.0.0.1");
    verify(repo, never()).findByFileId(any());
  }

  @Test
  void withoutIps_returnsEveryHost_asBefore() {
    when(repo.existsByFileId(fileId)).thenReturn(true);
    when(repo.findByFileId(fileId)).thenReturn(List.of(identity("10.0.0.1"), identity("10.0.0.9")));

    assertThat(controller.getHostIdentities(fileId, null).getBody()).hasSize(2);
    verify(repo, never()).findByFileIdAndIpIn(any(), any());
  }

  @Test
  void legacyFileWithNoIdentities_isStillBackfilledFirst() {
    when(repo.existsByFileId(fileId)).thenReturn(false);
    when(repo.findByFileIdAndIpIn(any(), any())).thenReturn(List.of());

    controller.getHostIdentities(fileId, List.of("10.0.0.1"));

    verify(adjudicator).adjudicateFile(fileId);
  }
}
