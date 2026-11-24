package com.tracepcap.knowledge.question;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Severity;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Alerts verbatim from the 2026-11-10 NetSupport and 2025-01-22 fake-authenticator exercises. */
class RemoteAccessQuestionTest {

  private static Finding alert(String summary, String host, String external) {
    return new Finding(
        "ids-alert", summary, Severity.CRITICAL, Grade.INFERRED, "suricata",
        List.of(EntityRef.host(host), EntityRef.external(external)), List.of(), Map.of());
  }

  private static List<Answer> answers(Finding... findings) {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    for (Finding f : findings) b.addFinding(f);
    return new RemoteAccessQuestion().answer(b.build());
  }

  @Test
  void aRemoteAdminCheckinToTheInternet_isSurfaced_neverCalledMalware() {
    List<Answer> a =
        answers(
            alert("ET INFO NetSupport Remote Admin Checkin (sid:2035892 sev:3)", "10.11.10.147", "93.152.209.36"),
            alert("ET INFO NetSupport Remote Admin Checkin (sid:2035892 sev:3)", "10.11.10.147", "93.152.209.36"));
    assertThat(a).singleElement().satisfies(x -> {
      assertThat(x.attributes()).containsEntry("host", "10.11.10.147")
          .containsEntry("tool", "NetSupport").containsEntry("external", "93.152.209.36");
      assertThat(x.headline()).contains("confirm this one is sanctioned").doesNotContain("C2");
      assertThat(x.basis()).hasSize(1);
    });
  }

  @Test
  void eachToolAndServerIsItsOwnAnswer() {
    List<Answer> a =
        answers(
            alert("ET POLICY TeamViewer Dyngate User-Agent (sid:2009475 sev:1)", "10.1.17.215", "185.188.32.26"),
            alert("ET INFO NetSupport Remote Admin Checkin (sid:2035892 sev:3)", "10.1.17.215", "93.152.209.36"));
    assertThat(a).extracting(x -> x.attributes().get("tool")).containsExactly("TeamViewer", "NetSupport");
  }

  @Test
  void dnsLookupsAndMalwareRules_areNotRemoteAccessSessions() {
    assertThat(
            answers(
                alert("ET INFO TeamViewer RMM Domain (teamviewer .com) in DNS Lookup (sid:2060630 sev:3)", "10.1.17.215", "8.8.8.8"),
                alert("ET MALWARE NetSupport RAT with System Information (sid:2035895 sev:1)", "10.11.10.147", "93.152.209.36")))
        .isEmpty();
  }

  @Test
  void aVendorLookupIsNotASession() {
    // Holdout 2024-11-26: NetSupport's GeoLocation lookup to geo.netsupportsoftware.com.
    assertThat(answers(alert("ET POLICY NetSupport GeoLocation Lookup Request (sid:2034559 sev:1)",
        "10.11.26.183", "104.26.1.231"))).isEmpty();
  }

  @Test
  void anNdpiIdentifiedTool_isASessionToo_withoutAnyAlert() {
    Finding ndpi = new Finding(
        com.tracepcap.knowledge.contributor.RemoteAccessAppContributor.REMOTE_ACCESS_APP,
        "nDPI identified AnyDesk between 10.0.0.5 and 51.89.1.1", Severity.MEDIUM, Grade.INFERRED, "ndpi",
        List.of(EntityRef.host("10.0.0.5"), EntityRef.external("51.89.1.1")), List.of(), Map.of("tool", "AnyDesk"));
    assertThat(answers(ndpi)).singleElement()
        .satisfies(x -> assertThat(x.attributes()).containsEntry("tool", "AnyDesk").containsEntry("external", "51.89.1.1"));
  }

  @Test
  void requestCountsFromCutRecords_sayTheyAreOfTheRecordsKept() {
    // #1284: 252 check-ins fired, 102 records kept. "(102×)" alone would read as the real count.
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    b.addFinding(alert("ET REMOTE_ACCESS NetSupport Remote Admin Checkin (sid:2035892 sev:3)", "10.11.10.147", "93.152.209.36"));
    b.addEntity(EntityRef.external("93.152.209.36"), Map.of(
        com.tracepcap.knowledge.contributor.IdsAlertRecordContributor.ALERT_REQUESTS,
        List.of("POST http://93.152.209.36/fakeurl.htm (102×)"),
        com.tracepcap.knowledge.contributor.IdsAlertRecordContributor.ALERT_RECORDS_KEPT, 102,
        com.tracepcap.knowledge.contributor.IdsAlertRecordContributor.ALERT_COUNT, 252));

    assertThat(new RemoteAccessQuestion().answer(b.build())).singleElement().satisfies(x ->
        assertThat(x.basis()).contains(
            "In the 102 alert records kept, alerts fired on: POST http://93.152.209.36/fakeurl.htm (102×)"));
  }
}
