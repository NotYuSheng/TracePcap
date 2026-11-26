package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Suricata's krb5 records become grouped replies (#1267). The fixtures are the krb5 lines Suricata
 * 8.0.8 logged for PCAP-ATTACK's kerbrute password spray and Mimikatz Skeleton Key captures
 * (github.com/sbousseaden/PCAP-ATTACK).
 */
class KerberosRecordsTest {

  private final SuricataService suricata = new SuricataService(new SuricataEngine());

  @Test
  void anErrorNamesTheAccountOfTheRequestItAnswers() throws IOException {
    List<KerberosRecords.Exchange> all = exchanges("CA_kerbrute_passwordspray_kerberos_AS-REQ");

    assertThat(all).filteredOn(x -> "KDC_ERR_C_PRINCIPAL_UNKNOWN".equals(x.errorCode()))
        .extracting(KerberosRecords.Exchange::account)
        .containsExactlyInAnyOrder("admin", "bob", "svc-01", "HD01", "HD02", "admin02", "svc-02");
    assertThat(all).filteredOn(x -> "KDC_ERR_PREAUTH_FAILED".equals(x.errorCode()))
        .extracting(KerberosRecords.Exchange::account)
        .containsExactlyInAnyOrder("administrator", "backdoor");
    assertThat(all).allSatisfy(x -> {
      assertThat(x.client()).isEqualTo("172.16.66.1");
      assertThat(x.kdc()).isEqualTo("172.16.66.36");
    });
  }

  @Test
  void aTicketKeepsItsEncryption_andTheKdcIsTheSideOnPort88() throws IOException {
    // Logged server-first (picked up mid-stream): the KDC still comes out as the KDC.
    List<KerberosRecords.Exchange> all = exchanges("lm_mimikazt_skeleton_kerberos_rc4_etype");

    assertThat(all).filteredOn(x -> "KRB_AS_REP".equals(x.msgType())).singleElement().satisfies(x -> {
      assertThat(x.account()).isEqualTo("backdoor");
      assertThat(x.encryption()).isEqualTo("rc4-hmac");
      assertThat(x.weak()).isTrue();
      assertThat(x.client()).isEqualTo("172.16.66.1");
      assertThat(x.kdc()).isEqualTo("172.16.66.36");
    });
    assertThat(all).filteredOn(x -> "KRB_TGS_REP".equals(x.msgType()))
        .allSatisfy(x -> assertThat(x.weak()).isFalse());
  }

  /** Parses a fixture and applies it to one conversation per flow in it, oriented client → KDC. */
  private List<KerberosRecords.Exchange> exchanges(String name) throws IOException {
    SuricataService.Eve eve = SuricataService.Eve.empty();
    Map<String, PcapParserService.ConversationInfo> convs = new LinkedHashMap<>();
    ObjectMapper json = new ObjectMapper();
    try (InputStream in = getClass().getResourceAsStream("/suricata-krb5/" + name + ".eve.json")) {
      assertThat(in).as(name).isNotNull();
      for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
        suricata.parseEveLine(line, eve);
        JsonNode r = json.readTree(line);
        boolean srcIsKdc = r.path("src_port").asInt() == 88;
        String client = srcIsKdc ? r.path("dest_ip").asText() : r.path("src_ip").asText();
        int port = srcIsKdc ? r.path("dest_port").asInt() : r.path("src_port").asInt();
        String kdc = srcIsKdc ? r.path("src_ip").asText() : r.path("dest_ip").asText();
        convs.computeIfAbsent(r.path("proto").asText() + client + port, k -> {
          PcapParserService.ConversationInfo c = new PcapParserService.ConversationInfo();
          c.setSrcIp(client);
          c.setSrcPort(port);
          c.setDstIp(kdc);
          c.setDstPort(88);
          c.setTransport(r.path("proto").asText());
          c.setProtocol(r.path("proto").asText());
          c.setSuricataAlerts(new ArrayList<>());
          return c;
        });
      }
    }
    suricata.apply(eve, new ArrayList<>(convs.values()));
    List<KerberosRecords.Exchange> all = new ArrayList<>();
    convs.values().forEach(c -> all.addAll(c.getKerberosExchanges()));
    return all;
  }
}
