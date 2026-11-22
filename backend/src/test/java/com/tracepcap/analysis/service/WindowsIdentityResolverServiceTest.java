package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
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

  @Test
  void personDn_withRfc4514EscapedComma_extractsTheUnescapedName() {
    // RFC 4514: a literal comma inside a CN value is backslash-escaped so it isn't read as the
    // attribute separator. The group must consume the escape pair (not truncate at it), and the
    // returned value must be the human-readable name without the wire-format backslash.
    assertThat(
            WindowsIdentityResolverService.personNameFromDn(
                "CN=Collier\\, Clark,CN=Users,DC=wiresharkworkshop,DC=online"))
        .isEqualTo("Collier, Clark");
  }

  @Test
  void personDn_withRfc4514HexEscape_isDecoded() {
    // \20 is an escaped space; the decoded name is "Van Damme", not "Van\20Damme".
    assertThat(
            WindowsIdentityResolverService.personNameFromDn(
                "CN=Van\\20Damme,CN=Users,DC=example,DC=com"))
        .isEqualTo("Van Damme");
  }

  // ── NTLM (#1234) ───────────────────────────────────────────────────────────
  // Rows as tshark prints them: frame|src|dst|ldap.baseObject|krb msg_type|krb CName|epoch|
  // ntlmssp.messagetype|ntlmssp.auth.username|ntlmssp.auth.domain

  private final WindowsIdentityResolverService resolver = new WindowsIdentityResolverService();

  @Test
  void ntlmSignIn_isRecordedAsASignInWithItsDomain() {
    var logons =
        resolver.logonsFromRows(
            List.of("412|10.1.17.215|10.1.17.2||||1722307129.43|3|jsmith|CONTOSO"));
    assertThat(logons).singleElement().satisfies(l -> {
      assertThat(l.ip()).isEqualTo("10.1.17.215");
      assertThat(l.username()).isEqualTo("jsmith");
      assertThat(l.source()).isEqualTo(WindowsIdentityResolverService.SOURCE_NTLM_AUTH);
      assertThat(l.domain()).isEqualTo("CONTOSO");
      assertThat(l.directoryEntry()).isNull();
      assertThat(l.isCandidateOnly()).isFalse();
    });
    assertThat(WindowsIdentityResolverService.isSignIn(logons.get(0).source())).isTrue();
  }

  @Test
  void ntlm_machineAccountsAndAnonymousSessions_areNotSignIns() {
    // Verbatim from the 2024-07-30 training capture: one machine-account sign-in, then anonymous
    // SMB sessions, which tshark prints as the literal NULL.
    var logons =
        resolver.logonsFromRows(
            List.of(
                "275|172.16.1.66|172.16.1.4||||1722307129.433463000|3|DESKTOP-SKBR25F$|WIRESHARKWORKSH",
                "9913|172.16.1.66|172.16.1.4||||1722307270.497131000|3|NULL|NULL"));
    assertThat(logons).isEmpty();
  }

  @Test
  void ntlm_onlyTheAuthenticateMessageCounts_andRepeatsAggregate() {
    var logons =
        resolver.logonsFromRows(
            List.of(
                // A CHALLENGE (type 2) carries no client account.
                "10|10.0.0.5|10.0.0.1||||1700000000.0|2||",
                "11|10.0.0.5|10.0.0.1||||1700000001.0|3|ccollier|CORP",
                "90|10.0.0.5|10.0.0.1||||1700000060.0|3|ccollier|CORP"));
    assertThat(logons).singleElement().satisfies(l -> {
      assertThat(l.username()).isEqualTo("ccollier");
      assertThat(l.seenCount()).isEqualTo(2);
      assertThat(l.firstSeen()).isBefore(l.lastSeen());
    });
  }

  @Test
  void ntlm_inTheSameFrameAsAnLdapSearch_bothAreRead() {
    var logons =
        resolver.logonsFromRows(
            List.of(
                "7|10.0.0.5|10.0.0.1|CN=Clark Collier,CN=Users,DC=corp,DC=local|||1700000000.0|3|ccollier|CORP"));
    assertThat(logons)
        .extracting(WindowsIdentityResolverService.Logon::source)
        .containsExactlyInAnyOrder(
            WindowsIdentityResolverService.SOURCE_NTLM_AUTH, WindowsIdentityResolverService.SOURCE_LDAP_DN);
  }

  @Test
  void rowsWithoutTheNtlmColumns_stillParse() {
    // Kerberos-only output, as before #1234.
    var logons =
        resolver.logonsFromRows(List.of("5|10.0.0.5|10.0.0.1||10|ccollier|1700000000.0"));
    assertThat(logons).singleElement()
        .extracting(WindowsIdentityResolverService.Logon::source)
        .isEqualTo(WindowsIdentityResolverService.SOURCE_KERBEROS_AS_REQ);
  }

  // ── SAMR full names ────────────────────────────────────────────────────────
  // Columns 10-11: samr.samr_UserInfo21.account_name, full_name. The reply goes DC -> client.

  @Test
  void samrQueryUserInfoReply_namesThePersonBehindTheAccount_forTheClientThatAsked() {
    // Verbatim from the 2026-01-31 Lumma training capture.
    var logons =
        resolver.logonsFromRows(
            List.of("358|10.1.21.2|10.1.21.58||||1769555064.0||||gwyatt|Gabriel Wyatt"));
    assertThat(logons).singleElement().satisfies(l -> {
      assertThat(l.ip()).isEqualTo("10.1.21.58");
      assertThat(l.source()).isEqualTo(WindowsIdentityResolverService.SOURCE_SAMR_USER_INFO);
      assertThat(l.username()).isEqualTo("Gabriel Wyatt");
      assertThat(l.directoryEntry()).isEqualTo("gwyatt");
    });
    assertThat(WindowsIdentityResolverService.fullNamesByIp(logons))
        .containsEntry("10.1.21.58", java.util.Map.of("gwyatt", "Gabriel Wyatt"));
  }

  @Test
  void aSamrAnswer_isNotASignIn() {
    var logons =
        resolver.logonsFromRows(
            List.of("90|10.8.15.4|10.8.15.133||||1723680600.0||||plucero|Pierce Lucero"));
    assertThat(logons).hasSize(1); // recorded, for the timeline
    assertThat(WindowsIdentityResolverService.toClaims(logons)).isEmpty(); // but not a sign-in
  }
}
