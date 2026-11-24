package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * One TCP connection is one conversation, whatever Wireshark labels each packet. Keying on the label
 * split a TLS connection into a "TCP" row (the handshake) and a "TLSV1.2" row (the records).
 */
class ConversationKeyTest {

  @Test
  void theKeyIsTheTransport_notThePacketsLabel() {
    assertThat(PcapParserService.transportOf("49739", "", "TCP")).isEqualTo("TCP");
    assertThat(PcapParserService.transportOf("49739", "", "TLSV1.2")).isEqualTo("TCP");
    assertThat(PcapParserService.transportOf("", "53", "DNS")).isEqualTo("UDP");
    assertThat(PcapParserService.transportOf("", "", "ICMP")).isEqualTo("ICMP");
  }

  @Test
  void aBareTransportLabel_givesWayToASpecificOne() {
    assertThat(PcapParserService.isBareTransport("TCP")).isTrue();
    assertThat(PcapParserService.isBareTransport("UDP")).isTrue();
    assertThat(PcapParserService.isBareTransport(null)).isTrue();
    assertThat(PcapParserService.isBareTransport("TLSV1.2")).isFalse();
    assertThat(PcapParserService.isBareTransport("HTTP")).isFalse();
  }
}
