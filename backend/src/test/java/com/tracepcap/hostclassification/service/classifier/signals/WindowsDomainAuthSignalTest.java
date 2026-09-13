package com.tracepcap.hostclassification.service.classifier.signals;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.service.WindowsIdentityResolverService;
import com.tracepcap.analysis.service.WindowsIdentityResolverService.Claim;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.HostProfile;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class WindowsDomainAuthSignalTest {

  private final WindowsDomainAuthSignal signal = new WindowsDomainAuthSignal();

  private HostContext ctx(List<Claim> claims) {
    return new HostContext(
        "172.16.1.66", new HostProfile(), 128, null, null, null, null, Set.of(), claims);
  }

  private Claim kerberos(String name) {
    return new Claim("172.16.1.66", name, WindowsIdentityResolverService.SOURCE_KERBEROS_AS_REQ);
  }

  private Claim ldap(String name) {
    return new Claim("172.16.1.66", name, WindowsIdentityResolverService.SOURCE_LDAP_DN);
  }

  @Test
  void kerberosClaim_votesLaptopDesktopStrongly_andNamesThePrincipal() {
    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(List.of(kerberos("ccollier"))), board);

    assertThat(board.scores())
        .containsEntry(DeviceTypes.LAPTOP_DESKTOP, WindowsDomainAuthSignal.KERBEROS_WEIGHT);
    assertThat(board.reasonsFor(DeviceTypes.LAPTOP_DESKTOP))
        .anySatisfy(r -> assertThat(r).contains("\"ccollier\"").contains("Kerberos AS-REQ"));
  }

  @Test
  void ldapOnlyClaim_votesLaptopDesktopWeakly() {
    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(List.of(ldap("Clark Collier"))), board);

    assertThat(board.scores())
        .containsEntry(DeviceTypes.LAPTOP_DESKTOP, WindowsDomainAuthSignal.LDAP_WEIGHT);
    assertThat(board.reasonsFor(DeviceTypes.LAPTOP_DESKTOP))
        .anySatisfy(r -> assertThat(r).contains("\"Clark Collier\"").contains("LDAP"));
  }

  @Test
  void bothSources_addBothVotes_kerberosWeightedHigher() {
    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(List.of(kerberos("ccollier"), ldap("Clark Collier"))), board);

    assertThat(board.scores())
        .containsEntry(
            DeviceTypes.LAPTOP_DESKTOP,
            WindowsDomainAuthSignal.KERBEROS_WEIGHT + WindowsDomainAuthSignal.LDAP_WEIGHT);
    assertThat(board.reasonsFor(DeviceTypes.LAPTOP_DESKTOP)).hasSize(2);
  }

  @Test
  void noClaims_addsNothing() {
    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(List.of()), board);

    assertThat(board.scores()).isEmpty();
  }
}
