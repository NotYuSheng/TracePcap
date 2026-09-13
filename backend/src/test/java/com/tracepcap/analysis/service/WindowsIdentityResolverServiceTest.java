package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link WindowsIdentityResolverService}'s pure parsing helpers — the DN-shape
 * discriminator and the machine-account exclusion (#809) — using DN/principal strings taken
 * verbatim from a real capture (a genuine certificate-template DN, a genuine person DN, a genuine
 * machine-account principal), not synthesized. Extracting individual LDAP frames out of a real pcap
 * into a small standalone fixture was tried and abandoned: LDAP dissection depends on TCP stream
 * reassembly context that a single stripped-out frame does not carry, so tshark cannot re-dissect
 * it correctly in isolation. These pure-function tests exercise exactly the same discriminator logic
 * without that fragility.
 */
class WindowsIdentityResolverServiceTest {

  @Test
  void personDn_underUsersContainer_extractsTheCn() {
    assertThat(
            WindowsIdentityResolverService.personNameFromDn(
                "CN=Clark Collier,CN=Users,DC=wiresharkworkshop,DC=online"))
        .isEqualTo("Clark Collier");
  }

  @Test
  void personDn_isCaseInsensitiveOnTheContainerName() {
    assertThat(
            WindowsIdentityResolverService.personNameFromDn(
                "cn=Clark Collier,cn=users,dc=example,dc=com"))
        .isEqualTo("Clark Collier");
  }

  @Test
  void infrastructureDn_underConfiguration_isNotAPerson() {
    // Real false positive found against a live capture (#809): a certificate-template DN
    // legitimately carries a displayName/cn attribute request, but is not a person object.
    assertThat(
            WindowsIdentityResolverService.personNameFromDn(
                "CN=Certificate Templates,CN=Public Key Services,CN=Services,"
                    + "CN=Configuration,DC=wiresharkworkshop,DC=online"))
        .isNull();
  }

  @Test
  void otherDnShapes_underNeitherUsersNorMatchingPattern_areNotPeople() {
    assertThat(
            WindowsIdentityResolverService.personNameFromDn(
                "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com"))
        .isNull();
    assertThat(WindowsIdentityResolverService.personNameFromDn("DC=example,DC=com")).isNull();
  }

  @Test
  void machineAccountPrincipal_endsWithDollarSign_isExcluded() {
    assertThat(WindowsIdentityResolverService.isMachineAccount("desktop-skbr25f$")).isTrue();
    assertThat(WindowsIdentityResolverService.isMachineAccount("DESKTOP-SKBR25F$")).isTrue();
  }

  @Test
  void humanPrincipal_isNotExcluded() {
    assertThat(WindowsIdentityResolverService.isMachineAccount("ccollier")).isFalse();
  }
}
