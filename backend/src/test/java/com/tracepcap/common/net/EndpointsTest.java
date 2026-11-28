package com.tracepcap.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class EndpointsTest {

  @Test
  void bracketsIpv6_soThePortReadsAsAPort() {
    assertThat(Endpoints.of("10.0.0.1", 443)).isEqualTo("10.0.0.1:443");
    assertThat(Endpoints.of("fd00::1", 443)).isEqualTo("[fd00::1]:443");
    assertThat(Endpoints.of("fd00::1", "*")).isEqualTo("[fd00::1]:*");
    assertThat(Endpoints.of("fd00::1", null)).isEqualTo("fd00::1");
  }
}
