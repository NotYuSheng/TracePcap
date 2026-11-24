package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The whole Suricata alert is kept (#1265), from both directions of a conversation. */
class SuricataAlertRecordTest {

  /** Trimmed from the 2024-11-26 NetSupport holdout's eve.json. */
  private static final String CHECKIN =
      "{\"timestamp\":\"2024-11-26T04:50:45.123456+0000\",\"event_type\":\"alert\","
          + "\"src_ip\":\"10.11.26.183\",\"src_port\":53362,\"dest_ip\":\"194.180.191.64\",\"dest_port\":443,"
          + "\"proto\":\"TCP\",\"alert\":{\"action\":\"allowed\",\"gid\":1,\"signature_id\":2035892,\"rev\":2,"
          + "\"signature\":\"ET INFO NetSupport Remote Admin Checkin\",\"category\":\"Misc activity\",\"severity\":3,"
          + "\"metadata\":{\"signature_severity\":[\"Informational\"],\"confidence\":[\"High\"],"
          + "\"attack_target\":[\"Client_Endpoint\"]}},"
          + "\"http\":{\"hostname\":\"194.180.191.64\",\"url\":\"http://194.180.191.64/fakeurl.htm\","
          + "\"http_user_agent\":\"NetSupport Manager/1.3\",\"http_method\":\"POST\",\"status\":200}}";

  private static final String RESPONSE =
      "{\"timestamp\":\"2024-11-26T04:50:46.000000+0000\",\"event_type\":\"alert\","
          + "\"src_ip\":\"194.180.191.64\",\"src_port\":443,\"dest_ip\":\"10.11.26.183\",\"dest_port\":53362,"
          + "\"proto\":\"TCP\",\"alert\":{\"signature_id\":2035893,\"signature\":\"ET INFO NetSupport Remote Admin Response\","
          + "\"category\":\"Misc activity\",\"severity\":3}}";

  private final SuricataService suricata = new SuricataService(new SuricataEngine());

  @Test
  void keepsTimeDirectionMetadataAndTheRequest() {
    SuricataService.Eve eve = SuricataService.Eve.empty();
    suricata.parseEveLine(CHECKIN, eve);
    PcapParserService.ConversationInfo conv = conversation();
    suricata.apply(eve, List.of(conv));

    assertThat(conv.getIdsAlertEvents()).singleElement().satisfies(a -> {
      assertThat(a.time()).isEqualTo(LocalDateTime.ofInstant(
          LocalDateTime.of(2024, 11, 26, 4, 50, 45, 123_456_000).toInstant(ZoneOffset.UTC), ZoneId.systemDefault()));
      assertThat(a.srcIp()).isEqualTo("10.11.26.183");
      assertThat(a.sid()).isEqualTo(2035892L);
      assertThat(a.rev()).isEqualTo(2);
      assertThat(a.category()).isEqualTo("Misc activity");
      assertThat(a.meta("signature_severity")).isEqualTo("Informational");
      assertThat(a.meta("confidence")).isEqualTo("High");
      assertThat(a.httpMethod()).isEqualTo("POST");
      assertThat(a.httpUrl()).isEqualTo("http://194.180.191.64/fakeurl.htm");
      assertThat(a.httpStatus()).isEqualTo(200);
    });
  }

  @Test
  void theServersOwnAlerts_areKeptAlongsideTheClients() {
    // Keyed by the packet that fired: the reply sits under the reverse 5-tuple. Taking one
    // direction only dropped it whenever the client side had fired too.
    SuricataService.Eve eve = SuricataService.Eve.empty();
    suricata.parseEveLine(CHECKIN, eve);
    suricata.parseEveLine(RESPONSE, eve);
    PcapParserService.ConversationInfo conv = conversation();
    suricata.apply(eve, List.of(conv));

    assertThat(conv.getSuricataAlerts()).hasSize(2).anyMatch(s -> s.contains("Remote Admin Response"));
    assertThat(conv.getIdsAlertEvents()).extracting(SuricataService.AlertEvent::srcIp)
        .containsExactly("10.11.26.183", "194.180.191.64"); // oldest first
  }

  @Test
  void anUnreadableTimestampIsNull_notAFailure() {
    assertThat(SuricataService.eveTime("yesterday")).isNull();
    assertThat(SuricataService.eveTime(null)).isNull();
  }

  private static PcapParserService.ConversationInfo conversation() {
    PcapParserService.ConversationInfo c = new PcapParserService.ConversationInfo();
    c.setSrcIp("10.11.26.183");
    c.setSrcPort(53362);
    c.setDstIp("194.180.191.64");
    c.setDstPort(443);
    c.setProtocol("TCP");
    return c;
  }

  @Test
  void atMostTheCapIsKept_countedAsTheyCome() {
    SuricataService.Eve eve = SuricataService.Eve.empty();
    for (int i = 0; i < SuricataService.MAX_ALERT_EVENTS + 50; i++) {
      // a new client port each time: every alert on its own flow, the case the old sum was slow on
      suricata.parseEveLine(CHECKIN.replace("53362", String.valueOf(1024 + i % 60000)), eve);
    }
    assertThat(eve.alertEvents().values().stream().mapToInt(List::size).sum())
        .isEqualTo(SuricataService.MAX_ALERT_EVENTS);
  }

  @Test
  void oneNoisyConnection_keepsItsFirstHundred_andItsTrueCount() {
    // #1284: a single flow can't use up the capture's budget, and its count stays honest.
    SuricataService.Eve eve = SuricataService.Eve.empty();
    for (int i = 0; i < 150; i++) suricata.parseEveLine(CHECKIN, eve);
    suricata.parseEveLine(RESPONSE, eve); // the reply direction, same conversation
    PcapParserService.ConversationInfo conv = conversation();
    suricata.apply(eve, List.of(conv));

    assertThat(conv.getIdsAlertEvents()).hasSize(SuricataService.MAX_ALERT_EVENTS_PER_FLOW + 1);
    assertThat(conv.getIdsAlertTotal()).isEqualTo(151);
  }

  @Test
  void aFlowsCount_goesToTheFirstConversationOnIt_once() {
    SuricataService.Eve eve = SuricataService.Eve.empty();
    suricata.parseEveLine(CHECKIN, eve);
    suricata.parseEveLine(CHECKIN, eve);
    PcapParserService.ConversationInfo first = conversation(), second = conversation();
    suricata.apply(eve, List.of(first, second));

    assertThat(first.getIdsAlertTotal()).isEqualTo(2);
    assertThat(second.getIdsAlertTotal()).isZero();
  }
}
