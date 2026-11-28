package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.tracepcap.analysis.spi.ServiceLogRoles;
import com.tracepcap.common.settings.RuntimePolicy;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.hostlog.entity.DnsQueryLogEntity;
import com.tracepcap.hostlog.entity.HttpEndpointLogEntity;
import com.tracepcap.hostlog.repository.DnsQueryLogRepository;
import com.tracepcap.hostlog.repository.HttpEndpointLogRepository;
import com.tracepcap.hostlog.service.DnsQueryLogExtractor;
import com.tracepcap.hostlog.service.WebServerLogExtractor;
import java.io.File;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * The extractors read IPv6 packets too (#1357). {@code fixtures/ipv6-cases.pcap} (from {@code
 * ipv6-cases.gen.py}) holds only IPv6: a DNS answer, an HTTP request and its JSON response, a
 * Kerberos AS-REQ and two VRRPv3 adverts. Each pass used to ask tshark for {@code ip.src} only,
 * and found nothing here. Real tshark, as in the other *RealCaptureTest classes.
 */
class Ipv6ExtractionRealCaptureTest {

  private static final File PCAP =
      new File(Ipv6ExtractionRealCaptureTest.class.getResource("/fixtures/ipv6-cases.pcap").getFile());
  private static final FileEntity FILE = FileEntity.builder().id(UUID.randomUUID()).build();

  @Test
  @SuppressWarnings("unchecked")
  void dnsAnswersFromAnIpv6Resolver() {
    DnsQueryLogRepository repo = mock(DnsQueryLogRepository.class);
    RuntimePolicy policy = mock(RuntimePolicy.class);
    org.mockito.Mockito.when(policy.getInt(org.mockito.ArgumentMatchers.any())).thenReturn(10);
    org.mockito.Mockito.when(policy.getDouble(org.mockito.ArgumentMatchers.any())).thenReturn(0.5);
    new DnsQueryLogExtractor(repo, policy).extractAndPersist(FILE, PCAP);
    ArgumentCaptor<List<DnsQueryLogEntity>> rows = ArgumentCaptor.forClass(List.class);
    verify(repo).saveAll(rows.capture());
    assertThat(rows.getValue()).singleElement().satisfies(r -> {
      assertThat(r.getServerIp()).isEqualTo("fd00::53");
      assertThat(r.getQueryName()).isEqualTo("intranet.example");
      assertThat(r.getResolvedIps()).isEqualTo("fd00::80");
    });
  }

  @Test
  @SuppressWarnings("unchecked")
  void httpToAnIpv6Server() {
    HttpEndpointLogRepository repo = mock(HttpEndpointLogRepository.class);
    var result = new WebServerLogExtractor(repo).extractAndPersist(FILE, PCAP);
    assertThat(result.roleByServerIp()).containsEntry("fd00::80", ServiceLogRoles.API);
    ArgumentCaptor<List<HttpEndpointLogEntity>> rows = ArgumentCaptor.forClass(List.class);
    verify(repo).saveAll(rows.capture());
    assertThat(rows.getValue()).singleElement().satisfies(r -> {
      assertThat(r.getServerIp()).isEqualTo("fd00::80");
      assertThat(r.getMethod()).isEqualTo("GET");
      assertThat(r.getPath()).isEqualTo("/api/v1/items");
    });
  }

  @Test
  void aKerberosLogonFromAnIpv6Client() {
    var logons = new WindowsIdentityResolverService().resolveLogons(PCAP);
    assertThat(logons).anySatisfy(l -> {
      assertThat(l.ip()).isEqualTo("fd00::10");
      assertThat(l.username()).isEqualTo("dave");
    });
  }

  @Test
  void aVrrpv3VirtualAddressOverIpv6() {
    var found = new FailoverAddressResolverService().resolve(PCAP);
    assertThat(found).containsKey("fd00::fe");
    assertThat(found.get("fd00::fe").protocol()).isEqualTo("VRRP");
    assertThat(found.get("fd00::fe").members()).containsExactly("fe80::2", "fe80::3");
  }
}
