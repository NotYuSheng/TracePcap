package com.tracepcap.knowledge.contributor;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.IdsAlertLookup.IdsAlertFacts;
import com.tracepcap.knowledge.question.C2Question;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class IdsAlertRecordContributorTest {

  private static IdsAlertFacts alert(LocalDateTime t, String src, String dst, String method, String host, String url) {
    return new IdsAlertFacts(UUID.randomUUID(), t, src, 50000, dst, 443, 2035892L, 2,
        "ET INFO NetSupport Remote Admin Checkin", "Misc activity", 3, "Informational", "High", null,
        Map.of(), method, host, url, null, 200);
  }

  @Test
  void summarisesAServersAlerts_requestsMostFrequentFirst() {
    LocalDateTime t0 = LocalDateTime.of(2024, 11, 26, 12, 50, 45);
    List<IdsAlertFacts> l = new ArrayList<>();
    for (int i = 0; i < 3; i++)
      l.add(alert(t0.plusMinutes(i), "10.11.26.183", "194.180.191.64", "POST", "194.180.191.64", "/fakeurl.htm"));
    l.add(alert(t0.plusMinutes(9), "10.11.26.183", "194.180.191.64", "GET", null, "/x"));
    l.add(alert(t0, "10.11.26.183", "10.11.26.3", null, null, null)); // internal: not a server outside

    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    IdsAlertRecordContributor.post(l, b);
    var board = b.build();

    Map<String, Object> a = board.entity(EntityRef.external("194.180.191.64")).orElseThrow().attributes();
    assertThat(a).containsEntry(IdsAlertRecordContributor.ALERT_COUNT, 4)
        .containsEntry(IdsAlertRecordContributor.FIRST_ALERT, TrafficContributor.utc(t0))
        .containsEntry(IdsAlertRecordContributor.LAST_ALERT, TrafficContributor.utc(t0.plusMinutes(9)));
    assertThat(a.get(IdsAlertRecordContributor.ALERT_REQUESTS)).isEqualTo(List.of(
        "POST http://194.180.191.64/fakeurl.htm (3×)", "GET http://194.180.191.64/x"));
    assertThat(board.entity(EntityRef.external("10.11.26.3"))).isEmpty();
  }

  @Test
  void theC2AnswerCitesTheRequestsAndTheAlertSpan() {
    LocalDateTime t0 = LocalDateTime.of(2024, 11, 26, 12, 50, 45);
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef c2 = EntityRef.external("194.180.191.64");
    b.addRelationship(Relationship.of(c2, "c2-of", EntityRef.malware("NetSupport RAT"), Grade.INFERRED, "suricata"));
    IdsAlertRecordContributor.post(
        List.of(alert(t0, "10.11.26.183", "194.180.191.64", "POST", "194.180.191.64", "http://194.180.191.64/fakeurl.htm")), b);

    assertThat(new C2Question().answer(b.build())).singleElement().satisfies(ans -> {
      assertThat(ans.attributes()).containsEntry("requests", List.of("POST http://194.180.191.64/fakeurl.htm"));
      assertThat(ans.basis()).contains("Alerts fired on: POST http://194.180.191.64/fakeurl.htm");
      assertThat(ans.basis()).anyMatch(s -> s.startsWith("1 alert from "));
    });
  }

  @Test
  void theRemoteAccessAnswerCitesTheRequestsToo() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    b.addFinding(new com.tracepcap.knowledge.spi.Finding("ids-alert",
        "ET INFO NetSupport Remote Admin Checkin (sid:2035892 sev:3)", com.tracepcap.knowledge.spi.Severity.LOW,
        Grade.INFERRED, "suricata", List.of(EntityRef.host("10.11.26.183"), EntityRef.external("194.180.191.64")),
        List.of(), Map.of()));
    IdsAlertRecordContributor.post(List.of(alert(LocalDateTime.of(2024, 11, 26, 12, 50), "10.11.26.183",
        "194.180.191.64", "POST", "194.180.191.64", "/fakeurl.htm")), b);
    assertThat(new com.tracepcap.knowledge.question.RemoteAccessQuestion().answer(b.build())).singleElement()
        .satisfies(a -> assertThat(a.basis()).contains("Alerts fired on: POST http://194.180.191.64/fakeurl.htm"));
  }

  @Test
  void pastTheCap_theCountIsTheTrueOne_andTheLastAlertIsntClaimed() {
    // #1284: 2 records kept of 500 that fired. The last record kept isn't the last alert.
    LocalDateTime t0 = LocalDateTime.of(2024, 11, 26, 12, 50, 45);
    List<IdsAlertFacts> kept = List.of(
        alert(t0, "10.11.26.183", "194.180.191.64", "POST", "194.180.191.64", "/fakeurl.htm"),
        alert(t0.plusSeconds(5), "10.11.26.183", "194.180.191.64", "POST", "194.180.191.64", "/fakeurl.htm"));
    var counts = List.of(new com.tracepcap.analysis.spi.IdsAlertLookup.AlertCount(
        UUID.randomUUID(), "10.11.26.183", "194.180.191.64", 500, 2));
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef c2 = EntityRef.external("194.180.191.64");
    b.addRelationship(Relationship.of(c2, "c2-of", EntityRef.malware("NetSupport RAT"), Grade.INFERRED, "suricata"));
    IdsAlertRecordContributor.post(kept, counts, b);
    var board = b.build();

    Map<String, Object> a = board.entity(c2).orElseThrow().attributes();
    assertThat(a).containsEntry(IdsAlertRecordContributor.ALERT_COUNT, 500)
        .containsEntry(IdsAlertRecordContributor.ALERT_RECORDS_KEPT, 2)
        .containsEntry(IdsAlertRecordContributor.FIRST_ALERT, TrafficContributor.utc(t0))
        .doesNotContainKey(IdsAlertRecordContributor.LAST_ALERT);
    assertThat(new C2Question().answer(board)).singleElement().satisfies(ans -> {
      assertThat(ans.attributes()).doesNotContainKey("lastAlert");
      assertThat(ans.basis()).anyMatch(s -> s.startsWith("500 alerts from ")
          && s.contains("records kept for the first 2 only"));
    });
  }

  @Test
  void aServerWhoseRecordsWereAllCut_isStillCounted() {
    var counts = List.of(new com.tracepcap.analysis.spi.IdsAlertLookup.AlertCount(
        UUID.randomUUID(), "10.11.26.183", "203.0.113.9", 7, 0));
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    IdsAlertRecordContributor.post(List.of(), counts, b);

    assertThat(b.build().entity(EntityRef.external("203.0.113.9")).orElseThrow().attributes())
        .containsEntry(IdsAlertRecordContributor.ALERT_COUNT, 7)
        .containsEntry(IdsAlertRecordContributor.ALERT_RECORDS_KEPT, 0)
        .doesNotContainKey(IdsAlertRecordContributor.FIRST_ALERT);
  }
}
