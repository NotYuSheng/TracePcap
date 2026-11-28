package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** The address a reverse-DNS (PTR) question names, for both families (#1354). */
class ReverseDnsNameTest {

  @Test
  void ipv4() {
    assertThat(HostnameResolverService.arpaToIp("4.3.2.1.in-addr.arpa.")).isEqualTo("1.2.3.4");
    assertThat(HostnameResolverService.arpaToIp("3.2.1.in-addr.arpa")).isNull(); // a zone
    assertThat(HostnameResolverService.arpaToIp("x.3.2.1.in-addr.arpa")).isNull();
  }

  @Test
  void ipv6_isWrittenAsTsharkWritesAddresses() {
    String q = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.IP6.ARPA.";
    assertThat(HostnameResolverService.arpaToIp(q)).isEqualTo("2001:db8::1");
    assertThat(HostnameResolverService.arpaToIp("8.b.d.0.1.0.0.2.ip6.arpa")).isNull(); // a zone
    assertThat(HostnameResolverService.arpaToIp(q.replace("8.b.d", "8.bb.d"))).isNull();
  }

  @Test
  void anythingElse() {
    assertThat(HostnameResolverService.arpaToIp("example.com")).isNull();
    assertThat(HostnameResolverService.arpaToIp(null)).isNull();
  }
}
