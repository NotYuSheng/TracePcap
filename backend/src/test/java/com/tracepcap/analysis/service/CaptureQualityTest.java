package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.dto.CaptureQualityResponse.Note;
import com.tracepcap.analysis.entity.CaptureStatsEntity;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Capture quality (#1268): Suricata's anomaly and stats records, and the notes made from them. */
class CaptureQualityTest {

  private final SuricataService suricata = new SuricataService(new SuricataEngine());

  /** Trimmed from Suricata 8's eve.json for the 2024-11-26 holdout. */
  private static final String ANOMALY =
      "{\"timestamp\":\"2024-11-26T04:50:45.000000+0000\",\"event_type\":\"anomaly\",\"src_ip\":\"10.11.26.183\","
          + "\"src_port\":53318,\"dest_ip\":\"10.11.26.3\",\"dest_port\":139,\"proto\":\"TCP\",\"anomaly\":{"
          + "\"app_proto\":\"smb\",\"type\":\"applayer\",\"event\":\"APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION\","
          + "\"layer\":\"proto_detect\"}}";

  private static final String STATS =
      "{\"timestamp\":\"2024-11-26T05:40:00.000000+0000\",\"event_type\":\"stats\",\"stats\":{"
          + "\"decoder\":{\"pkts\":26922,\"invalid\":3},\"tcp\":{\"sessions\":142,\"reassembly_gap\":2,"
          + "\"stream_depth_reached\":5,\"ssn_memcap_drop\":0,\"segment_memcap_drop\":1},\"flow\":{\"memcap\":0}}}";

  @Test
  void anomaliesLandOnTheirConversation_andStatsAreKept() {
    SuricataService.Eve eve = SuricataService.Eve.empty();
    suricata.parseEveLine(ANOMALY, eve);
    suricata.parseEveLine(STATS, eve);
    PcapParserService.ConversationInfo c = new PcapParserService.ConversationInfo();
    c.setSrcIp("10.11.26.183");
    c.setSrcPort(53318);
    c.setDstIp("10.11.26.3");
    c.setDstPort(139);
    c.setProtocol("TCP");
    suricata.apply(eve, List.of(c));

    assertThat(c.getSuricataAnomalies()).singleElement().satisfies(a -> {
      assertThat(a.event()).isEqualTo("APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION");
      assertThat(a.appProto()).isEqualTo("smb");
      assertThat(a.layer()).isEqualTo("proto_detect");
    });
    assertThat(eve.stats().get())
        .isEqualTo(new SuricataService.CaptureStats(26922L, 3L, 142L, 2L, 5L, 1L));
  }

  @Test
  void aCompleteCapture_hasNoNotes() {
    assertThat(CaptureQualityService.notes(100, 2,
        CaptureStatsEntity.builder().reassemblyGaps(0L).invalidPackets(0L).memcapDrops(0L).streamDepthReached(0L).build()))
        .isEmpty();
  }

  @Test
  void gapsAndMemoryComeFirst_asWarnings() {
    List<Note> n = CaptureQualityService.notes(100, 40,
        CaptureStatsEntity.builder().reassemblyGaps(2L).invalidPackets(3L).memcapDrops(1L).streamDepthReached(5L).build());
    assertThat(n).extracting(Note::getKind).containsExactly("gaps", "memcap", "midstream", "invalid", "depth");
    assertThat(n.get(0).getLevel()).isEqualTo("warning");
    assertThat(n.get(2).getText()).startsWith("40 of 100 TCP connections (40%) were already open");
  }

  @Test
  void noOutcomeOnAnyConnection_isNotMeasured_notAllMidstream() {
    // A capture analysed before connection outcomes existed: every TCP outcome is null.
    assertThat(CaptureQualityService.notes(100, 100, null)).isEmpty();
  }

  @Test
  void suricataReadingNoneOfTheCapture_isTheFirstWarning() {
    // The Ultimate PCAP: 49,503 packets over four link types; Suricata decoded 0 and succeeded.
    List<Note> n = CaptureQualityService.notes(642, 38,
        CaptureStatsEntity.builder().packets(0L).reassemblyGaps(0L).build(), 49_503L);
    assertThat(n).first().satisfies(x -> {
      assertThat(x.getKind()).isEqualTo("suricata-unread");
      assertThat(x.getLevel()).isEqualTo("warning");
      assertThat(x.getText()).contains("0 of 49503 packets");
    });
  }

  @Test
  void suricataReadingNearlyAll_isFine() {
    assertThat(CaptureQualityService.notes(10, 0, CaptureStatsEntity.builder().packets(990L).build(), 1000L))
        .isEmpty();
  }
}
