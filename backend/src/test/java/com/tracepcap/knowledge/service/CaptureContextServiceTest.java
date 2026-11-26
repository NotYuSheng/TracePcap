package com.tracepcap.knowledge.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.CaptureQualityLookup.QualityNote;
import com.tracepcap.analysis.spi.ConversationLookup.HostPair;
import com.tracepcap.common.adjudication.ManualEvidenceEntity;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.knowledge.service.CaptureContextService.Candidate;
import com.tracepcap.knowledge.service.CaptureContextService.Mix;
import com.tracepcap.knowledge.service.CaptureContextService.Vantage;
import com.tracepcap.knowledge.service.CaptureContextService.VantagePoint;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Capture context (docs/architecture/investigation-framework.rst, "Capture context"). */
class CaptureContextServiceTest {

  private static Mix mix(List<HostPair> pairs) {
    return CaptureContextService.mix(pairs, IpLocality::isLocal);
  }

  private static VantagePoint vantage(List<HostPair> pairs, long answeredPorts, ManualEvidenceEntity... ev) {
    Mix m = mix(pairs);
    return CaptureContextService.decide(CaptureContextService.infer(m, answeredPorts), m, List.of(ev));
  }

  /** {@code n} outside hosts each opening one conversation to the sensor, which opens {@code out}. */
  private static List<HostPair> sensor(int n, int out) {
    List<HostPair> pairs = new ArrayList<>();
    for (int i = 1; i <= n; i++) pairs.add(new HostPair("192.168.100.28", "61.0.0." + i, 1, 0, 1));
    pairs.add(new HostPair("192.168.100.28", "203.0.113.9", out, out, 0));
    return pairs;
  }

  @Test
  void aHostProbedByManyHostsOnManyPortsReadsAsASensor() {
    VantagePoint v = vantage(sensor(18, 3), 18);
    assertThat(v.key()).isEqualTo(Vantage.SENSOR.key());
    assertThat(v.described()).isEqualTo("On a honeypot or sensor (192.168.100.28)");
    assertThat(v.basis()).isEqualTo("MACHINE");
    assertThat(v.contested()).isFalse();
    assertThat(v.reason()).contains("18 hosts opened 18 conversations to it on 18 ports; it opened 3");
  }

  @Test
  void aHostAnsweringFewPortsIsAServerNotASensor() {
    VantagePoint v = vantage(sensor(18, 3), 2);
    assertThat(v.key()).isEqualTo(Vantage.SERVER.key());
  }

  @Test
  void aHostThatOpensItsOwnConversationsIsOneHostsTraffic() {
    List<HostPair> pairs = List.of(
        new HostPair("10.8.15.133", "10.8.15.4", 200, 200, 0),
        new HostPair("10.8.15.133", "203.0.113.9", 300, 300, 0));
    VantagePoint v = vantage(pairs, 0);
    assertThat(v.key()).isEqualTo(Vantage.CLIENT.key());
    assertThat(v.host()).isEqualTo("10.8.15.133");
    assertThat(v.reason()).contains("it opened 500 conversations; no host opened one to it");
    assertThat(v.candidates()).extracting(Candidate::label).containsExactly(Vantage.CLIENT.label());
  }

  @Test
  void aCompromisedSensorAttackingOutKeepsTheSensorAsARunnerUp() {
    VantagePoint v = vantage(sensor(15, 40_000), 54);
    assertThat(v.key()).isEqualTo(Vantage.CLIENT.key());
    assertThat(v.candidates()).extracting(Candidate::label)
        .containsExactly(Vantage.CLIENT.label(), Vantage.SENSOR.label());
  }

  @Test
  void manyInternalHostsTalkingToEachOtherIsInsideTheLan() {
    List<HostPair> pairs = new ArrayList<>();
    for (int i = 1; i <= 10; i++) {
      pairs.add(new HostPair("10.0.0." + i, "10.0.0." + (i + 1), 4, 4, 0));
      pairs.add(new HostPair("10.0.0." + i, "198.51.100." + i, 6, 6, 0));
    }
    VantagePoint v = vantage(pairs, 0);
    assertThat(v.key()).isEqualTo(Vantage.LAN.key());
    assertThat(v.host()).isNull();
  }

  @Test
  void manyInternalHostsMostlyReachingOutIsTheUplink() {
    List<HostPair> pairs = new ArrayList<>();
    for (int i = 1; i <= 10; i++) pairs.add(new HostPair("10.0.0." + i, "198.51.100." + i, 9, 9, 0));
    pairs.add(new HostPair("10.0.0.1", "10.0.0.2", 1, 1, 0));
    assertThat(vantage(pairs, 0).key()).isEqualTo(Vantage.UPLINK.key());
  }

  @Test
  void tooFewConversationsLeavesItUndeterminedWithWhy() {
    VantagePoint v = vantage(List.of(new HostPair("98.114.205.102", "192.150.11.111", 5, 4, 1)), 1);
    assertThat(v.determined()).isFalse();
    assertThat(v.reason()).isEqualTo("only 5 conversations, too few to tell where it was taken");
  }

  @Test
  void noDominantHostAndNoInternalAddressesSuggestsSettingPrivateRanges() {
    List<HostPair> pairs = new ArrayList<>();
    for (int i = 1; i <= 10; i++) pairs.add(new HostPair("198.51.100." + i, "203.0.113." + i, 2, 2, 0));
    VantagePoint v = vantage(pairs, 0);
    assertThat(v.determined()).isFalse();
    assertThat(v.reason()).contains("add them as private ranges");
  }

  @Test
  void analystEvidenceAddsItsWeightAndCanTipTheVote() {
    ManualEvidenceEntity ev = ManualEvidenceEntity.builder()
        .label("sensor").weight(50).reason("this is our Cowrie box").entityKey("capture").build();
    VantagePoint v = vantage(sensor(18, 3), 2, ev);
    // SERVER 65 against SENSOR 25 + 50: the analyst's evidence tips it, but only just: contested.
    assertThat(v.candidates()).extracting(Candidate::label)
        .containsExactly(Vantage.SENSOR.label(), Vantage.SERVER.label());
    assertThat(v.contested()).isTrue();
    assertThat(v.candidates().get(0).reasons()).contains("analyst evidence: this is our Cowrie box");
  }

  @Test
  void anOverrideWinsOutrightAndKeepsTheMachineCandidates() {
    VantagePoint inferred = vantage(sensor(18, 3), 2);
    VantagePoint v = CaptureContextService.overridden(inferred, "On a honeypot or sensor", "Cowrie", "ana");
    assertThat(v.key()).isEqualTo(Vantage.SENSOR.key());
    assertThat(v.basis()).isEqualTo("HUMAN");
    assertThat(v.host()).isEqualTo("192.168.100.28");
    assertThat(v.reason()).isEqualTo("Cowrie");
    assertThat(v.overriddenBy()).isEqualTo("ana");
    assertThat(v.candidates()).isEqualTo(inferred.candidates());
  }

  @Test
  void anOverrideWithALabelOfItsOwnIsKeptAsWritten() {
    VantagePoint v = CaptureContextService.overridden(
        vantage(sensor(18, 3), 18), "SPAN port on the DMZ switch", null, "ana");
    assertThat(v.key()).isEqualTo("other");
    assertThat(v.described()).isEqualTo("SPAN port on the DMZ switch");
    assertThat(v.reason()).isEqualTo("set by an analyst");
  }

  @Test
  void completenessIsPartialWhenTrafficIsMissing() {
    var c = CaptureContextService.completeness(List.of(
        new QualityNote("gaps", "warning", "3 gaps"), new QualityNote("midstream", "info", "x")));
    assertThat(c.level()).isEqualTo("partial");
    assertThat(c.label()).isEqualTo(
        "Partial: gaps in TCP streams, connections already open when it began");
  }

  @Test
  void theIdsInspectionDepthAloneDoesNotQualifyCompleteness() {
    var c = CaptureContextService.completeness(List.of(new QualityNote("depth", "info", "2 sessions")));
    assertThat(c.level()).isEqualTo("complete");
    assertThat(c.notes()).hasSize(1);
  }

  @Test
  void theTimeSpanReadsAsADurationAndItsEnds() {
    var t = CaptureContextService.timeSpan(LocalDateTime.of(2024, 8, 15, 8, 9),
        LocalDateTime.of(2024, 8, 15, 8, 42), 33 * 60_000L);
    assertThat(t.label()).isEqualTo("33 min, 2024-08-15 08:09 to 08:42 UTC");
    assertThat(CaptureContextService.duration(16_219)).isEqualTo("16 s");
    assertThat(CaptureContextService.duration(85_987_389)).isEqualTo("24 h");
    assertThat(CaptureContextService.duration(6143L * 86_400_000)).isEqualTo("17 years");
  }
}
