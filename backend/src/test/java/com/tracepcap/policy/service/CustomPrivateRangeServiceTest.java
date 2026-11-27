package com.tracepcap.policy.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.policy.entity.CustomPrivateRangeEntity;
import com.tracepcap.policy.entity.IpClassification;
import com.tracepcap.policy.service.CustomPrivateRangeService.Override;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link CustomPrivateRangeService#overrideFor}. It drives
 * {@code ChangeDetectionService.isPrivate}, so a bad match flips classification across the pipeline.
 * The method does not touch the repository, so a null repository is sufficient here.
 */
class CustomPrivateRangeServiceTest {

  private final CustomPrivateRangeService service = new CustomPrivateRangeService(null, null, null);

  private static CustomPrivateRangeEntity range(String cidr, IpClassification classification) {
    return CustomPrivateRangeEntity.builder().cidr(cidr).classification(classification).build();
  }

  @Test
  void overrideFor_publicRange_forcesPublic() {
    List<CustomPrivateRangeEntity> ranges = List.of(range("10.0.0.0/8", IpClassification.PUBLIC));
    assertThat(service.overrideFor("10.1.2.3", ranges)).isEqualTo(Override.FORCE_PUBLIC);
  }

  @Test
  void overrideFor_privateRange_forcesPrivate() {
    List<CustomPrivateRangeEntity> ranges = List.of(range("203.0.113.0/24", IpClassification.PRIVATE));
    assertThat(service.overrideFor("203.0.113.7", ranges)).isEqualTo(Override.FORCE_PRIVATE);
  }

  @Test
  void overrideFor_noMatch_returnsNone() {
    List<CustomPrivateRangeEntity> ranges = List.of(range("10.0.0.0/8", IpClassification.PUBLIC));
    assertThat(service.overrideFor("192.168.1.1", ranges)).isEqualTo(Override.NONE);
  }

  @Test
  void overrideFor_overlappingRanges_firstMatchWins() {
    // Ranges arrive most-recent-first; the first matching entry should win regardless of the second.
    List<CustomPrivateRangeEntity> ranges =
        List.of(
            range("10.1.0.0/16", IpClassification.PUBLIC),
            range("10.0.0.0/8", IpClassification.PRIVATE));
    assertThat(service.overrideFor("10.1.2.3", ranges)).isEqualTo(Override.FORCE_PUBLIC);
  }

  @Test
  void overrideFor_nullIp_returnsNone() {
    List<CustomPrivateRangeEntity> ranges = List.of(range("10.0.0.0/8", IpClassification.PUBLIC));
    assertThat(service.overrideFor(null, ranges)).isEqualTo(Override.NONE);
  }

  @Test
  void overrideFor_nullOrEmptyRanges_returnsNone() {
    assertThat(service.overrideFor("10.1.2.3", null)).isEqualTo(Override.NONE);
    assertThat(service.overrideFor("10.1.2.3", List.of())).isEqualTo(Override.NONE);
  }

  // --- rows saved before #1351 keep their text, and are still the same entry ---------------

  private static CustomPrivateRangeService withRows(
      com.tracepcap.policy.repository.CustomPrivateRangeRepository repo, CustomPrivateRangeEntity... rows) {
    org.mockito.Mockito.when(repo.findByNetworkIdIsNullOrderByCreatedAtDesc()).thenReturn(List.of(rows));
    org.mockito.Mockito.when(repo.save(org.mockito.ArgumentMatchers.any()))
        .thenAnswer(inv -> inv.getArgument(0));
    return new CustomPrivateRangeService(repo,
        org.mockito.Mockito.mock(com.tracepcap.governance.PermissionService.class),
        org.mockito.Mockito.mock(com.tracepcap.governance.AuditLogService.class));
  }

  @Test
  void savingARangeFindsTheRowSavedEarlierInAnotherSpelling() {
    var repo = org.mockito.Mockito.mock(com.tracepcap.policy.repository.CustomPrivateRangeRepository.class);
    CustomPrivateRangeEntity old = range("fd00::/8", IpClassification.PRIVATE); // stored short
    old.setId(7L);
    CustomPrivateRangeEntity hostBits = range("10.1.2.3/8", IpClassification.PRIVATE);
    hostBits.setId(8L);
    var svc = withRows(repo, old, hostBits);

    var v6 = com.tracepcap.policy.dto.CustomPrivateRangeDto.builder()
        .cidr("fd00:0:0:0:0:0:0:0/8").classification("PUBLIC").build();
    assertThat(svc.create(v6).getId()).isEqualTo(7L); // updated, not a second row
    var v4 = com.tracepcap.policy.dto.CustomPrivateRangeDto.builder()
        .cidr("10.0.0.0/8").classification("PUBLIC").build();
    assertThat(svc.create(v4).getId()).isEqualTo(8L);
  }

  @Test
  void theListAnswersInTheFormASaveWrites() {
    var repo = org.mockito.Mockito.mock(com.tracepcap.policy.repository.CustomPrivateRangeRepository.class);
    var svc = withRows(repo, range("10.1.2.3/8", IpClassification.PRIVATE));
    assertThat(svc.list()).extracting(com.tracepcap.policy.dto.CustomPrivateRangeDto::getCidr)
        .containsExactly("10.0.0.0/8");
  }
}
