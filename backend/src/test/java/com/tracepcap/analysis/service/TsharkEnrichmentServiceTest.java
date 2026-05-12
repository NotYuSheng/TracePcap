package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TsharkEnrichmentServiceTest {

  // --- extractAppLayerProto ---

  @Test
  void extractAppLayerProto_pureTcp_returnsNull() {
    assertThat(TsharkEnrichmentService.extractAppLayerProto("eth:ethertype:ip:tcp", "TCP"))
        .isNull();
  }

  @Test
  void extractAppLayerProto_pureUdp_returnsNull() {
    assertThat(TsharkEnrichmentService.extractAppLayerProto("eth:ethertype:ip:udp", "UDP"))
        .isNull();
  }

  @Test
  void extractAppLayerProto_icmpv6_caseInsensitive_returnsNull() {
    // l4proto from IP_PROTO map is "ICMPv6"; stack entry is lowercase "icmpv6"
    assertThat(TsharkEnrichmentService.extractAppLayerProto("eth:ethertype:ip:icmpv6", "ICMPv6"))
        .isNull();
  }

  @Test
  void extractAppLayerProto_httpOverTcp_returnsHttp() {
    assertThat(TsharkEnrichmentService.extractAppLayerProto("eth:ethertype:ip:tcp:http", "TCP"))
        .isEqualTo("HTTP");
  }

  @Test
  void extractAppLayerProto_dnsOverUdp_returnsDns() {
    assertThat(TsharkEnrichmentService.extractAppLayerProto("eth:ethertype:ip:udp:dns", "UDP"))
        .isEqualTo("DNS");
  }

  @Test
  void extractAppLayerProto_tlsOverTcp_returnsTls() {
    assertThat(TsharkEnrichmentService.extractAppLayerProto("eth:ethertype:ip:tcp:tls", "TCP"))
        .isEqualTo("TLS");
  }

  @Test
  void extractAppLayerProto_httpOverTls_returnsDeepestLayer() {
    // Tunnelled stack: deepest wins
    assertThat(TsharkEnrichmentService.extractAppLayerProto("eth:ethertype:ip:tcp:tls:http", "TCP"))
        .isEqualTo("HTTP");
  }

  @Test
  void extractAppLayerProto_quicHttp2_returnsHttp2() {
    assertThat(
            TsharkEnrichmentService.extractAppLayerProto("eth:ethertype:ip:udp:quic:http2", "UDP"))
        .isEqualTo("HTTP2");
  }

  @Test
  void extractAppLayerProto_vlanTagged_returnsAppLayer() {
    assertThat(
            TsharkEnrichmentService.extractAppLayerProto(
                "eth:ethertype:vlan:ethertype:ip:tcp:http", "TCP"))
        .isEqualTo("HTTP");
  }

  @Test
  void extractAppLayerProto_emptyStack_returnsNull() {
    assertThat(TsharkEnrichmentService.extractAppLayerProto("", "TCP")).isNull();
  }

  @Test
  void extractAppLayerProto_dataAtTop_returnsNull() {
    // "data" is a non-informative label Wireshark emits when it cannot dissect further
    assertThat(TsharkEnrichmentService.extractAppLayerProto("eth:ethertype:ip:tcp:data", "TCP"))
        .isNull();
  }

  @Test
  void extractAppLayerProto_frameAtTop_returnsNull() {
    assertThat(TsharkEnrichmentService.extractAppLayerProto("frame:eth:ethertype:ip:frame", "TCP"))
        .isNull();
  }

  @Test
  void extractAppLayerProto_sllAtTop_returnsNull() {
    // SLL (Linux cooked capture) at the top means no app-layer dissection
    assertThat(TsharkEnrichmentService.extractAppLayerProto("sll:ethertype:ip:tcp:sll", "TCP"))
        .isNull();
  }

  // --- resolveProtoNumber ---

  @Test
  void resolveProtoNumber_commonProtocols_returnExpectedNames() {
    assertThat(TsharkEnrichmentService.resolveProtoNumber("1")).isEqualTo("ICMP");
    assertThat(TsharkEnrichmentService.resolveProtoNumber("2")).isEqualTo("IGMP");
    assertThat(TsharkEnrichmentService.resolveProtoNumber("6")).isEqualTo("TCP");
    assertThat(TsharkEnrichmentService.resolveProtoNumber("17")).isEqualTo("UDP");
    assertThat(TsharkEnrichmentService.resolveProtoNumber("47")).isEqualTo("GRE");
    assertThat(TsharkEnrichmentService.resolveProtoNumber("50")).isEqualTo("ESP");
    assertThat(TsharkEnrichmentService.resolveProtoNumber("51")).isEqualTo("AH");
    assertThat(TsharkEnrichmentService.resolveProtoNumber("103")).isEqualTo("PIM");
    assertThat(TsharkEnrichmentService.resolveProtoNumber("112")).isEqualTo("VRRP");
    assertThat(TsharkEnrichmentService.resolveProtoNumber("132")).isEqualTo("SCTP");
  }

  @Test
  void resolveProtoNumber_icmpv6Override_appliesNormalization() {
    // IANA keyword is "IPv6-ICMP"; override maps it to "ICMPv6"
    assertThat(TsharkEnrichmentService.resolveProtoNumber("58")).isEqualTo("ICMPv6");
  }

  @Test
  void resolveProtoNumber_ospfOverride_appliesNormalization() {
    // IANA keyword is "OSPFIGP"; override maps it to "OSPF"
    assertThat(TsharkEnrichmentService.resolveProtoNumber("89")).isEqualTo("OSPF");
  }

  @Test
  void resolveProtoNumber_unknownNumber_returnsUpperCasedNumber() {
    assertThat(TsharkEnrichmentService.resolveProtoNumber("200")).isEqualTo("200");
  }

  @Test
  void resolveProtoNumber_emptyString_returnsUnknown() {
    assertThat(TsharkEnrichmentService.resolveProtoNumber("")).isEqualTo("UNKNOWN");
  }

  // --- normalizeL7Protocol ---

  @Test
  void normalizeL7Protocol_lowercaseInput_uppercases() {
    assertThat(TsharkEnrichmentService.normalizeL7Protocol("http")).isEqualTo("HTTP");
  }

  @Test
  void normalizeL7Protocol_stripsLeadingTheArticle() {
    assertThat(TsharkEnrichmentService.normalizeL7Protocol("The Microsoft")).isEqualTo("MICROSOFT");
  }

  @Test
  void normalizeL7Protocol_noArticle_uppercasesOnly() {
    assertThat(TsharkEnrichmentService.normalizeL7Protocol("tls")).isEqualTo("TLS");
  }
}
