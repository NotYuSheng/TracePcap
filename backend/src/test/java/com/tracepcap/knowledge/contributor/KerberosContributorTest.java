package com.tracepcap.knowledge.contributor;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.KerberosLookup.KerberosFacts;
import com.tracepcap.knowledge.question.KerberosAttackQuestion;
import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Kerberos attacks (#1267), from replies as PCAP-ATTACK's kerbrute and Skeleton Key captures
 * produce them (see KerberosRecordsTest), and a Windows domain's ordinary sign-ins as the negative.
 */
class KerberosContributorTest {

  private static final String C = "172.16.66.1", DC = "172.16.66.36";
  private static final LocalDateTime AT = LocalDateTime.of(2020, 7, 19, 21, 14, 41);

  @Test
  void kerbrute_isPasswordGuessingAcrossNineAccounts() {
    List<KerberosFacts> r = new ArrayList<>();
    for (String n : List.of("admin", "bob", "svc-01", "HD01", "HD02", "admin02", "svc-02")) r.add(error(n, "KDC_ERR_C_PRINCIPAL_UNKNOWN"));
    r.add(error("administrator", "KDC_ERR_PREAUTH_FAILED"));
    r.add(error("backdoor", "KDC_ERR_PREAUTH_FAILED"));
    r.add(error("normal", "KDC_ERR_PREAUTH_REQUIRED"));
    r.add(ticket("KRB_AS_REP", "normal", "krbtgt/THREEBEESCO.COM", "aes256-cts-hmac-sha1-96", false));

    List<Answer> answers = answers(r);
    assertThat(answers).singleElement().satisfies(a -> {
      assertThat(a.attributes()).containsEntry("technique", KerberosContributor.PASSWORD_GUESSING)
          .containsEntry("client", C).containsEntry("kdc", DC);
      assertThat(a.headline()).startsWith(C + " failed to sign in at the domain controller " + DC)
          .contains("a wrong password for 2 accounts and 7 account names that don't exist")
          .contains("user enumeration");
      assertThat(a.basis()).contains("Wrong password for 2 accounts: administrator, backdoor");
    });
  }

  @Test
  void aWindowsDomainsOrdinarySignIns_postNothing() {
    // What every clean exercise shows: pre-authentication asked for, then AES tickets.
    List<KerberosFacts> r = new ArrayList<>();
    for (int i = 0; i < 6; i++) r.add(error("user" + i, "KDC_ERR_PREAUTH_REQUIRED"));
    r.add(error("cifs/fileserver", "KDC_ERR_S_PRINCIPAL_UNKNOWN"));
    r.add(ticket("KRB_AS_REP", "user1", "krbtgt/CORP", "aes256-cts-hmac-sha1-96", false));
    r.add(ticket("KRB_TGS_REP", "user1", "cifs/dc", "aes256-cts-hmac-sha1-96", false));
    assertThat(answers(r)).isEmpty();
  }

  @Test
  void aFewWrongPasswords_areATypo_notAnAttack() {
    List<KerberosFacts> r = List.of(error("alice", "KDC_ERR_PREAUTH_FAILED"), error("bob", "KDC_ERR_PREAUTH_FAILED"));
    assertThat(answers(r)).isEmpty();
  }

  @Test
  void manyWrongPasswordsForOneAccount_isGuessingAgainstIt() {
    KerberosFacts many = new KerberosFacts(UUID.randomUUID(), AT, C, DC, "KRB_ERROR", "administrator", "krbtgt/CORP",
        "CORP", "KDC_ERR_PREAUTH_FAILED", null, false, 25);
    assertThat(answers(List.of(many))).singleElement()
        .satisfies(a -> assertThat(a.headline()).contains("25 wrong passwords for one").contains("one account"));
  }

  @Test
  void skeletonKey_isAWeakSignInTicketFromAKdcThatUsesAes() {
    List<KerberosFacts> r = List.of(
        ticket("KRB_AS_REP", "backdoor", "krbtgt/THREEBEESCO.COM", "rc4-hmac", true),
        ticket("KRB_TGS_REP", "backdoor", "cifs/01566s-win16-ir", "aes256-cts-hmac-sha1-96", false));
    assertThat(answers(r)).singleElement().satisfies(a -> {
      assertThat(a.attributes()).containsEntry("technique", KerberosContributor.WEAK_TICKET);
      assertThat(a.headline()).contains("a sign-in ticket encrypted with RC4 or DES").contains("Skeleton Key");
      assertThat(a.basis()).contains("Sign-in ticket for backdoor, rc4-hmac");
    });
  }

  @Test
  void weakServiceTickets_pointAtKerberoasting() {
    List<KerberosFacts> r = List.of(
        ticket("KRB_TGS_REP", "jdoe", "MSSQLSvc/db.corp.local:1433", "rc4-hmac", true),
        ticket("KRB_TGS_REP", "jdoe", "HTTP/web.corp.local", "rc4-hmac", true),
        ticket("KRB_AS_REP", "jdoe", "krbtgt/CORP", "aes256-cts-hmac-sha1-96", false));
    assertThat(answers(r)).singleElement().satisfies(a -> assertThat(a.headline()).contains("Kerberoasting"));
  }

  @Test
  void aDomainThatOnlyDoesRc4_isOld_notAttacked() {
    List<KerberosFacts> r = List.of(
        ticket("KRB_AS_REP", "jdoe", "krbtgt/CORP", "rc4-hmac", true),
        ticket("KRB_TGS_REP", "jdoe", "cifs/dc", "rc4-hmac", true));
    assertThat(answers(r)).isEmpty();
  }

  private static List<Answer> answers(List<KerberosFacts> r) {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    KerberosContributor.post(r, b);
    CaseKnowledge board = b.build();
    return new KerberosAttackQuestion().answer(board);
  }

  private static KerberosFacts error(String account, String code) {
    return new KerberosFacts(UUID.randomUUID(), AT, C, DC, "KRB_ERROR", account, "krbtgt/THREEBEESCO.COM",
        "THREEBEESCO.COM", code, null, false, 1);
  }

  private static KerberosFacts ticket(String type, String account, String service, String enc, boolean weak) {
    return new KerberosFacts(UUID.randomUUID(), AT, C, DC, type, account, service, "THREEBEESCO.COM", null, enc, weak, 1);
  }
}
