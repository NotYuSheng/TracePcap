package com.tracepcap.knowledge.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.knowledge.question.C2Question;
import com.tracepcap.knowledge.question.DataTransferQuestion;
import com.tracepcap.knowledge.question.DownloadsQuestion;
import com.tracepcap.knowledge.question.KerberosAttackQuestion;
import com.tracepcap.knowledge.question.LateralMovementQuestion;
import com.tracepcap.knowledge.question.MalwareQuestion;
import com.tracepcap.knowledge.question.RemoteAccessQuestion;
import com.tracepcap.knowledge.question.SignedInUserQuestion;
import com.tracepcap.knowledge.question.VictimQuestion;
import com.tracepcap.knowledge.service.CategoryCoverage.CategoryStatus;
import com.tracepcap.knowledge.service.CategoryCoverage.Status;
import com.tracepcap.knowledge.spi.Category;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** The four statuses (docs/architecture/investigation-framework.rst, "The four statuses"). */
class CategoryCoverageTest {

  private static final List<CategoryCatalogue.Entry> ENTRIES = new CategoryCatalogue(List.of(
      new VictimQuestion(), new SignedInUserQuestion(), new MalwareQuestion(), new C2Question(),
      new DownloadsQuestion(), new DataTransferQuestion(), new RemoteAccessQuestion(),
      new LateralMovementQuestion(), new KerberosAttackQuestion())).entries();

  private static Map<Category, CategoryStatus> run(
      Set<String> answered, Set<String> ruledOut, Set<String> l7, Set<String> apps) {
    return CategoryCoverage.compute(ENTRIES, answered, ruledOut, l7, apps).stream()
        .collect(Collectors.toMap(CategoryStatus::category, s -> s));
  }

  @Test
  void anAnswerAnswersEveryCategoryItsQuestionCovers() {
    var m = run(Set.of("c2"), Set.of(), Set.of("DNS"), Set.of());
    assertThat(m.get(Category.C2_SERVER).status()).isEqualTo(Status.ANSWERED);
    assertThat(m.get(Category.COMMAND_AND_CONTROL).status()).isEqualTo(Status.ANSWERED);
  }

  @Test
  void answeredBeatsRuledOut() {
    // One C2 confirmed, another candidate rejected: the category is answered.
    var m = run(Set.of("c2"), Set.of("c2"), Set.of(), Set.of());
    assertThat(m.get(Category.C2_SERVER).status()).isEqualTo(Status.ANSWERED);
  }

  @Test
  void candidatesAllRejectedIsRuledOut() {
    var m = run(Set.of(), Set.of("kerberos-attack"), Set.of("KERBEROS"), Set.of());
    assertThat(m.get(Category.CREDENTIAL_ACCESS).status()).isEqualTo(Status.RULED_OUT);
  }

  @Test
  void oneCheckRulingOutItsCandidateLeavesTheOthersOpen() {
    // Remote access rejected a TeamViewer peer; the c2 and malware checks concluded nothing.
    var m = run(Set.of(), Set.of("remote-access"), Set.of("DNS"), Set.of());
    assertThat(m.get(Category.COMMAND_AND_CONTROL).status()).isEqualTo(Status.OPEN);
    assertThat(m.get(Category.REMOTE_ACCESS_SERVER).status()).isEqualTo(Status.RULED_OUT);
  }

  @Test
  void aLeadInTheCaptureKeepsACategoryOpenThoughItsCheckHasNoTraffic() {
    // NTLM but no Kerberos: the Kerberos check can't run, but NTLM is still worth a look.
    CategoryStatus cred = run(Set.of(), Set.of(), Set.of("NTLMSSP"), Set.of())
        .get(Category.CREDENTIAL_ACCESS);
    assertThat(cred.status()).isEqualTo(Status.OPEN);
    assertThat(cred.leads()).extracting(CategoryCoverage.Lead::label).containsExactly("NTLM");
  }

  @Test
  void neverAndRarelyAreNotObservableWithTheirReason() {
    var m = run(Set.of(), Set.of(), Set.of("SMB2"), Set.of());
    assertThat(m.get(Category.ADVERSARY).status()).isEqualTo(Status.NOT_OBSERVABLE);
    assertThat(m.get(Category.PERSISTENCE).status()).isEqualTo(Status.NOT_OBSERVABLE);
    assertThat(m.get(Category.PERSISTENCE).reason()).contains("on the host");
  }

  @Test
  void missingTrafficIsNotObservableAndSaysWhich() {
    var m = run(Set.of(), Set.of(), Set.of("DNS", "TLS"), Set.of());
    CategoryStatus lateral = m.get(Category.LATERAL_MOVEMENT);
    assertThat(lateral.status()).isEqualTo(Status.NOT_OBSERVABLE);
    assertThat(lateral.reason()).isEqualTo("no SMB or DCE-RPC in this capture");
  }

  @Test
  void presentTrafficLeavesItOpen() {
    var m = run(Set.of(), Set.of(), Set.of("SMB2"), Set.of());
    assertThat(m.get(Category.LATERAL_MOVEMENT).status()).isEqualTo(Status.OPEN);
    assertThat(m.get(Category.LATERAL_MOVEMENT).unchecked()).isFalse();
  }

  @Test
  void aQuestionReadingAnyTrafficNeverGoesNotObservable() {
    // No HTTP, FTP or SMB: downloads are carved from any stream, so still open.
    var m = run(Set.of(), Set.of(), Set.of("QUIC"), Set.of());
    assertThat(m.get(Category.INITIAL_ACCESS).status()).isEqualTo(Status.OPEN);
    assertThat(m.get(Category.C2_SERVER).status()).isEqualTo(Status.OPEN);
  }

  @Test
  void aCategoryNoCheckCoversIsOpenNotNotObservable() {
    // The review's port-scan case: a gap in TracePcap mustn't read as a gap in the capture.
    CategoryStatus recon = run(Set.of(), Set.of(), Set.of(), Set.of()).get(Category.RECONNAISSANCE);
    assertThat(recon.status()).isEqualTo(Status.OPEN);
    assertThat(recon.unchecked()).isTrue();
    assertThat(recon.reason()).isEqualTo("no check covers this yet");
  }

  @Test
  void leadsLinkThePresentProtocolsByTheFilterTheyMatch() {
    var m = run(Set.of(), Set.of(), Set.of("TLS", "DNS", "SMB2"), Set.of("TLS", "SMBv23", "AnyDesk"));
    // TLS is linked by tshark's name even though nDPI has it too; SMB by nDPI's.
    assertThat(m.get(Category.C2_SERVER).leads())
        .extracting(CategoryCoverage.Lead::label, CategoryCoverage.Lead::query)
        .containsExactly(
            org.assertj.core.groups.Tuple.tuple("DNS", "l7Protocols=DNS"),
            org.assertj.core.groups.Tuple.tuple("TLS", "l7Protocols=TLS"));
    assertThat(m.get(Category.LATERAL_MOVEMENT).leads())
        .extracting(CategoryCoverage.Lead::query).containsExactly("apps=SMBv23");
    assertThat(m.get(Category.REMOTE_ACCESS_SERVER).leads())
        .extracting(CategoryCoverage.Lead::query).containsExactly("apps=AnyDesk");
  }

  @Test
  void notObservableCarriesNoLeads() {
    var m = run(Set.of(), Set.of(), Set.of("DNS"), Set.of());
    assertThat(m.get(Category.LATERAL_MOVEMENT).leads()).isEmpty();
  }

  private static CaptureContextService.CaptureContext context(String vantageKey, String label) {
    return context(vantageKey, label, 0);
  }

  private static CaptureContextService.CaptureContext context(
      String vantageKey, String label, long internalConversations) {
    var v = new CaptureContextService.VantagePoint(vantageKey, label, null,
        "MACHINE", 70, false, List.of(), vantageKey == null ? "too few to tell" : "why", null);
    return new CaptureContextService.CaptureContext(v,
        new CaptureContextService.Completeness("Complete", "complete", List.of()),
        new CaptureContextService.TimeSpan(null, null, 60_000L, "1 min, from to"),
        internalConversations);
  }

  private static Map<Category, CategoryStatus> withContext(
      CaptureContextService.CaptureContext ctx, Set<String> apps) {
    return CategoryCoverage.withContext(
            CategoryCoverage.compute(ENTRIES, Set.of(), Set.of(), Set.of(), apps), ctx)
        .stream().collect(Collectors.toMap(CategoryStatus::category, s -> s));
  }

  @Test
  void theCaptureContextAnswersItsThreeCategories() {
    var m = withContext(context("sensor", "On a honeypot or sensor"), Set.of());
    assertThat(m.get(Category.VANTAGE_POINT).status()).isEqualTo(Status.ANSWERED);
    assertThat(m.get(Category.VANTAGE_POINT).reason()).isEqualTo("On a honeypot or sensor (inferred)");
    assertThat(m.get(Category.COMPLETENESS).reason()).isEqualTo("Complete");
    assertThat(m.get(Category.TIME_SPAN).reason()).isEqualTo("1 min, from to");
  }

  @Test
  void anUndeterminedVantageStaysOpenWithWhy() {
    var m = withContext(context(null, null), Set.of());
    assertThat(m.get(Category.VANTAGE_POINT).status()).isEqualTo(Status.OPEN);
    assertThat(m.get(Category.VANTAGE_POINT).reason()).isEqualTo("too few to tell");
  }

  @Test
  void fromTheUplinkLateralMovementCantBeSeenUnlessThereIsTrafficForIt() {
    var m = withContext(context("uplink", "On the internet uplink"), Set.of());
    assertThat(m.get(Category.LATERAL_MOVEMENT).status()).isEqualTo(Status.NOT_OBSERVABLE);
    assertThat(m.get(Category.LATERAL_MOVEMENT).reason()).contains("a capture inside the LAN would show it");
    // SMB crossing the uplink is still worth a look.
    var withSmb = withContext(context("uplink", "On the internet uplink"), Set.of("SMBv23"));
    assertThat(withSmb.get(Category.LATERAL_MOVEMENT).status()).isEqualTo(Status.OPEN);
  }

  @Test
  void fromTheUplinkInternalTrafficInTheCaptureKeepsLateralMovementOpen() {
    var m = withContext(context("uplink", "On the internet uplink", 1500), Set.of());
    // Not the uplink's reason: with no SMB it is phase 2's "no SMB or DCE-RPC" (and with SMB, open).
    assertThat(m.get(Category.LATERAL_MOVEMENT).reason()).doesNotContain("uplink");
  }

  // ── The honeypot role ──────────────────────────────────────────────────────────────────────

  private static HoneypotRoleService.HostRole host(String ip, String label, String honeypot,
      String basis, String reason) {
    return new HoneypotRoleService.HostRole(ip, label, honeypot, basis, 80, false, List.of(),
        List.of(), reason, null);
  }

  private static CategoryStatus honeypot(HoneypotRoleService.HoneypotReport r) {
    return CategoryCoverage.withHoneypots(
            CategoryCoverage.compute(ENTRIES, Set.of(), Set.of(), Set.of(), Set.of()), r, null)
        .stream().filter(s -> s.category() == Category.HONEYPOT).findFirst().orElseThrow();
  }

  @Test
  void onASensorNoSignatureLeavesItOpenNotRuledOut() {
    var ctx = context("sensor", "On a honeypot or sensor");
    var s = CategoryCoverage.withHoneypots(
            CategoryCoverage.compute(ENTRIES, Set.of(), Set.of(), Set.of(), Set.of()),
            new HoneypotRoleService.HoneypotReport(List.of(), 0, 3, "v"), ctx)
        .stream().filter(x -> x.category() == Category.HONEYPOT).findFirst().orElseThrow();
    assertThat(s.status()).isEqualTo(Status.OPEN);
    assertThat(s.reason()).startsWith("the capture reads as taken on a honeypot or sensor")
        .contains("high-interaction honeypot");
  }

  @Test
  void aHostReadAsAHoneypotAnswersTheCategory() {
    var s = honeypot(new HoneypotRoleService.HoneypotReport(List.of(
        host("198.51.100.45", "Honeypot", "Dionaea", "MACHINE", "x")), 0, 2, "v"));
    assertThat(s.status()).isEqualTo(Status.ANSWERED);
    assertThat(s.unchecked()).isFalse();
    assertThat(s.reason()).isEqualTo("198.51.100.45 is a Dionaea honeypot (inferred)");
  }

  @Test
  void aSignatureWithoutEnoughElseLeavesItOpenWithWhy() {
    var s = honeypot(new HoneypotRoleService.HoneypotReport(List.of(
        host("203.0.113.5", null, "Cowrie", "MACHINE", "its signals add up to 30 points of the 60 a"
            + " honeypot needs")), 0, 3, "v"));
    assertThat(s.status()).isEqualTo(Status.OPEN);
    assertThat(s.reason()).isEqualTo("203.0.113.5 points at Cowrie, but its signals add up to 30"
        + " points of the 60 a honeypot needs");
  }

  @Test
  void serversCheckedWithNoMatchRuleItOut() {
    var s = honeypot(new HoneypotRoleService.HoneypotReport(List.of(), 0, 4, "v"));
    assertThat(s.status()).isEqualTo(Status.RULED_OUT);
    assertThat(s.reason()).isEqualTo("no server matched a honeypot signature (4 servers checked)");
  }

  @Test
  void anAnalystSayingNotAHoneypotRulesItOut() {
    var s = honeypot(new HoneypotRoleService.HoneypotReport(List.of(
        host("198.51.100.22", "Not a honeypot", null, "HUMAN", "bastion")), 0, 1, "v"));
    assertThat(s.status()).isEqualTo(Status.RULED_OUT);
    assertThat(s.reason()).isEqualTo("198.51.100.22 is not a honeypot (set by an analyst)");
  }

  @Test
  void serversWithOnlyAStockBannerAreCountedAndRuledOut() {
    var s = honeypot(new HoneypotRoleService.HoneypotReport(List.of(), 12, 1476, "v"));
    assertThat(s.status()).isEqualTo(Status.RULED_OUT);
    assertThat(s.reason()).isEqualTo("no server showed enough: 12 sent only a stock honeypot banner,"
        + " which real servers send too (1476 servers checked)");
  }

  @Test
  void noBannersAtAllLeaveItOpen() {
    var s = honeypot(new HoneypotRoleService.HoneypotReport(List.of(), 0, 0, "v"));
    assertThat(s.status()).isEqualTo(Status.OPEN);
    assertThat(s.reason()).contains("no server banners or certificates");
  }
}
