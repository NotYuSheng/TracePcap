package com.tracepcap.insights.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.WindowsIdentityClaimLookup;
import com.tracepcap.analysis.spi.WindowsIdentityClaimLookup.UsernameClaim;
import com.tracepcap.common.adjudication.HumanOverrideEntity;
import com.tracepcap.common.adjudication.HumanOverrideRepository;
import com.tracepcap.insights.entity.WindowsIdentityEntity;
import com.tracepcap.insights.repository.WindowsIdentityRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * The Windows-identity adjudication contract (#809): a human override ranks first and is never
 * contested; a Kerberos AS-REQ claim (MEASURED) outranks an LDAP DN claim (REPORTED) for the same
 * IP without averaging them; multiple distinct principals from the same source tier for one IP is
 * an explicit contest, not a quiet pick; an IP with no claims at all gets no row.
 */
class WindowsIdentityServiceTest {

  private final UUID fileId = UUID.randomUUID();
  private final WindowsIdentityClaimLookup lookup = mock(WindowsIdentityClaimLookup.class);
  private final WindowsIdentityRepository identityRepo = mock(WindowsIdentityRepository.class);
  private final HumanOverrideRepository overrideRepo = mock(HumanOverrideRepository.class);
  private final WindowsIdentityService service =
      new WindowsIdentityService(lookup, identityRepo, overrideRepo);

  private List<WindowsIdentityEntity> adjudicated() {
    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<WindowsIdentityEntity>> captor = ArgumentCaptor.forClass((Class) List.class);
    verify(identityRepo).saveAll(captor.capture());
    return captor.getValue();
  }

  private static UsernameClaim kerberos(String ip, String username) {
    return new UsernameClaim(ip, username, WindowsIdentityClaimLookup.SOURCE_KERBEROS_AS_REQ);
  }

  private static UsernameClaim ldap(String ip, String username) {
    return new UsernameClaim(ip, username, WindowsIdentityClaimLookup.SOURCE_LDAP_DN);
  }

  @Test
  void kerberosClaim_winsOutright_overLdapClaimForTheSameIp() {
    when(lookup.claimsForFile(fileId))
        .thenReturn(List.of(kerberos("172.16.1.66", "ccollier"), ldap("172.16.1.66", "Clark Collier")));
    when(overrideRepo.findByQuestionAndFileId(any(), any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    WindowsIdentityEntity id = adjudicated().get(0);
    assertThat(id.getPrimaryLabel()).isEqualTo("ccollier");
    assertThat(id.getBasis()).isEqualTo(WindowsIdentityEntity.BASIS_MACHINE);
    assertThat(id.isContested()).isFalse();
    // The LDAP claim is not discarded — it still rides along as corroboration.
    assertThat(id.getCandidates()).hasSize(2);
    assertThat(id.getCandidates())
        .anySatisfy(c -> assertThat(c).containsEntry("label", "Clark Collier"));
  }

  @Test
  void ldapOnlyClaim_becomesThePrimaryLabel_atLowerConfidence() {
    when(lookup.claimsForFile(fileId)).thenReturn(List.of(ldap("172.16.1.66", "Clark Collier")));
    when(overrideRepo.findByQuestionAndFileId(any(), any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    WindowsIdentityEntity id = adjudicated().get(0);
    assertThat(id.getPrimaryLabel()).isEqualTo("Clark Collier");
    assertThat(id.isContested()).isFalse();
  }

  @Test
  void multipleDistinctKerberosPrincipals_forOneIp_isContested() {
    // A shared kiosk: two different authenticated users seen from the same IP.
    when(lookup.claimsForFile(fileId))
        .thenReturn(List.of(kerberos("10.0.0.5", "alice"), kerberos("10.0.0.5", "bob")));
    when(overrideRepo.findByQuestionAndFileId(any(), any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    WindowsIdentityEntity id = adjudicated().get(0);
    assertThat(id.isContested()).isTrue();
    assertThat(id.getCandidates()).hasSize(2);
  }

  @Test
  void humanOverride_ranksAboveEverything_neverContested_andKeepsMachineCandidates() {
    when(lookup.claimsForFile(fileId)).thenReturn(List.of(kerberos("172.16.1.66", "ccollier")));
    HumanOverrideEntity override =
        HumanOverrideEntity.builder()
            .question("windows-identity")
            .fileId(fileId)
            .entityKey("172.16.1.66")
            .label("Clark Collier (confirmed)")
            .actor("alice")
            .build();
    when(overrideRepo.findByQuestionAndFileId("windows-identity", fileId)).thenReturn(List.of(override));

    service.adjudicateFile(fileId);

    WindowsIdentityEntity id = adjudicated().get(0);
    assertThat(id.getPrimaryLabel()).isEqualTo("Clark Collier (confirmed)");
    assertThat(id.getBasis()).isEqualTo(WindowsIdentityEntity.BASIS_HUMAN);
    assertThat(id.getConfidence()).isEqualTo(100);
    assertThat(id.isContested()).isFalse();
    // Overriding must not erase the machine's own claim from the explanation.
    assertThat(id.getCandidates()).anySatisfy(c -> assertThat(c).containsEntry("label", "ccollier"));
  }

  @Test
  void ipWithNoClaimsAndNoOverride_getsNoRowAtAll() {
    when(lookup.claimsForFile(fileId)).thenReturn(List.of());
    when(overrideRepo.findByQuestionAndFileId(any(), any())).thenReturn(List.of());

    service.adjudicateFile(fileId);

    assertThat(adjudicated()).isEmpty();
  }
}
