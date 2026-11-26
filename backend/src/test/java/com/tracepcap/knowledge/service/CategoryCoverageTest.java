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
}
