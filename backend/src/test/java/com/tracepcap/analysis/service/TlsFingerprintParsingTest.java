package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * #599: nDPI 6 reports JA4 instead of JA3C, so client JA3 comes from Suricata's TLS records, which
 * also fill TLS facts nDPI missed. The lines here are real output (discord.pcap) from the versions
 * in the backend image: nDPI 6.0 and Suricata 6.0.4.
 */
class TlsFingerprintParsingTest {

  private static final String NDPI_LINE =
      "\t9\tTCP 10.0.2.15:42834 <-> 162.159.128.233:443 [proto: 91.58/TLS.Discord][Stack: TLS.Discord]"
          + "[IP: 220/Cloudflare][Encrypted][Confidence: DPI][cat: Collaborative/15][Breed: Fun]"
          + "[3 pkts/451 bytes <-> 4 pkts/3257 bytes][Hostname/SNI: discord.com][Risk: ** TLS Cert Expired **]"
          + "[TLSv1.2][JA4: t12d1209h2_d34a8e72043a_b39be8c56a14][ServerNames: discord.com]";

  private static final String EVE_TLS =
      "{\"timestamp\":\"1970-01-01T07:30:42.233199+0730\",\"flow_id\":1993545580475056,\"event_type\":\"tls\","
          + "\"src_ip\":\"10.0.2.15\",\"src_port\":42834,\"dest_ip\":\"162.159.128.233\",\"dest_port\":443,\"proto\":\"6\","
          + "\"tls\":{\"subject\":\"C=US, O=Cloudflare, Inc., CN=sni.cloudflaressl.com\","
          + "\"issuerdn\":\"C=US, O=Cloudflare, Inc., CN=Cloudflare Inc ECC CA-3\",\"sni\":\"discord.com\","
          + "\"version\":\"TLS 1.2\",\"notbefore\":\"2021-01-19T00:00:00\",\"notafter\":\"2022-01-18T23:59:59\","
          + "\"ja3\":{\"hash\":\"6f5e62edfa5933b1332ddf8b9fb3ef9d\",\"string\":\"771,49195\"},"
          + "\"ja3s\":{\"hash\":\"9ebc57def2efb523f25c77af13aa6d48\",\"string\":\"771,49195,0\"}}}";

  private final SuricataService suricata = new SuricataService(new SuricataEngine());

  @Test
  void ndpi6_reportsJa4_whichIsKept() {
    Map<String, NdpiService.FlowData> flows = new HashMap<>();
    new NdpiService().parseFlowLine(NDPI_LINE, flows);
    NdpiService.FlowData flow = flows.values().iterator().next();
    assertThat(flow.ja4Client()).isEqualTo("t12d1209h2_d34a8e72043a_b39be8c56a14");
    assertThat(flow.ja3Client()).as("nDPI 6 no longer prints JA3C").isNull();
    assertThat(flow.hostname()).isEqualTo("discord.com");
  }

  @Test
  void suricataTls_fillsJa3AndTheVersion_inEitherDirection() {
    SuricataService.Eve eve = SuricataService.Eve.empty();
    suricata.parseEveLine(EVE_TLS, eve);

    // The conversation is keyed the other way round from Suricata's record.
    PcapParserService.ConversationInfo conv = conversation("162.159.128.233", 443, "10.0.2.15", 42834);
    suricata.apply(eve, List.of(conv));

    assertThat(conv.getJa3Client()).isEqualTo("6f5e62edfa5933b1332ddf8b9fb3ef9d");
    assertThat(conv.getJa3Server()).isEqualTo("9ebc57def2efb523f25c77af13aa6d48");
    assertThat(conv.getTlsVersion()).isEqualTo("TLS 1.2");
    assertThat(conv.getHostname()).isEqualTo("discord.com");
    assertThat(conv.getTlsIssuer()).contains("Cloudflare Inc ECC CA-3");
    assertThat(conv.getTlsNotAfter()).isEqualTo(LocalDateTime.of(2022, 1, 18, 23, 59, 59));
    assertThat(conv.getSuricataAlerts()).isEmpty();
  }

  @Test
  void suricataTls_neverReplacesWhatNdpiSet() {
    SuricataService.Eve eve = SuricataService.Eve.empty();
    suricata.parseEveLine(EVE_TLS, eve);
    PcapParserService.ConversationInfo conv = conversation("10.0.2.15", 42834, "162.159.128.233", 443);
    conv.setHostname("cdn.discordapp.com");
    conv.setJa3Server("00000000000000000000000000000000");

    suricata.apply(eve, List.of(conv));

    assertThat(conv.getHostname()).isEqualTo("cdn.discordapp.com");
    assertThat(conv.getJa3Server()).isEqualTo("00000000000000000000000000000000");
    assertThat(conv.getJa3Client()).isEqualTo("6f5e62edfa5933b1332ddf8b9fb3ef9d");
  }

  @Test
  void alertsStillParse_andOtherEventTypesAreIgnored() {
    SuricataService.Eve eve = SuricataService.Eve.empty();
    suricata.parseEveLine(
        "{\"event_type\":\"alert\",\"src_ip\":\"10.0.0.5\",\"src_port\":1234,\"dest_ip\":\"1.2.3.4\",\"dest_port\":80,"
            + "\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET MALWARE Test, one\",\"signature_id\":2014,\"severity\":1}}",
        eve);
    suricata.parseEveLine("{\"event_type\":\"flow\",\"src_ip\":\"10.0.0.5\",\"dest_ip\":\"1.2.3.4\"}", eve);
    suricata.parseEveLine("{\"event_type\":\"http\",\"src_ip\":\"10.0.0.5\",\"dest_ip\":\"1.2.3.4\",\"http\":{}}", eve);
    suricata.parseEveLine("not json", eve);

    PcapParserService.ConversationInfo conv = conversation("10.0.0.5", 1234, "1.2.3.4", 80);
    suricata.apply(eve, List.of(conv));
    // Unchanged: the comma in the signature is still replaced, so the label stays one filter token.
    assertThat(conv.getSuricataAlerts()).containsExactly("ET MALWARE Test; one (sid:2014 sev:1)");
    assertThat(eve.tls()).isEmpty();
    assertThat(conv.getTlsVersion()).isNull();
  }

  private static PcapParserService.ConversationInfo conversation(String src, int sport, String dst, int dport) {
    PcapParserService.ConversationInfo c = new PcapParserService.ConversationInfo();
    c.setSrcIp(src);
    c.setSrcPort(sport);
    c.setDstIp(dst);
    c.setDstPort(dport);
    c.setProtocol("TCP");
    return c;
  }
}
