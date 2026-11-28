package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

/**
 * Suricata writes IPv6 in full, tshark compressed (#1357). Checked on Suricata 8.0.8: an IPv6
 * alert's src_ip is "fd00:0000:0000:0000:0000:0000:0000:0010", where tshark writes "fd00::10".
 */
class SuricataEveAddressTest {

  @Test
  void anIpv6EveAddressIsWrittenAsTsharkWritesIt() throws Exception {
    var eve = new ObjectMapper().readTree(
        "{\"src_ip\":\"fd00:0000:0000:0000:0000:0000:0000:0010\",\"dest_ip\":\"10.0.0.1\",\"x\":\"x:y\"}");
    assertThat(SuricataService.eveAddress(eve, "src_ip")).isEqualTo("fd00::10");
    assertThat(SuricataService.eveAddress(eve, "dest_ip")).isEqualTo("10.0.0.1");
    var mapped = new ObjectMapper().readTree("{\"src_ip\":\"0000:0000:0000:0000:0000:ffff:0a00:0001\"}");
    assertThat(SuricataService.eveAddress(mapped, "src_ip")).isEqualTo("::ffff:10.0.0.1"); // as tshark writes it
    assertThat(SuricataService.eveAddress(eve, "x")).isEqualTo("x:y"); // not an address: unchanged
    assertThat(SuricataService.eveAddress(eve, "missing")).isNull();
  }
}
