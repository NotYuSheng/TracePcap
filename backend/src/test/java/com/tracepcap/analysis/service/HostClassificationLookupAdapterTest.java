package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * {@code HostFacts} promises callers a split, non-null {@code serviceRoles} list (#512 slice 6b).
 * That splitting used to live in HostClassificationsController; the port is only trustworthy if the
 * adapter does it for every consumer, including the ones that arrive later.
 */
class HostClassificationLookupAdapterTest {

  private static final UUID FILE = UUID.randomUUID();

  private final HostClassificationRepository repository = mock(HostClassificationRepository.class);
  private final HostClassificationLookupAdapter adapter =
      new HostClassificationLookupAdapter(repository);

  private static HostClassificationEntity host(String ip, String serviceRoles) {
    return HostClassificationEntity.builder()
        .ip(ip)
        .mac("02:00:00:00:00:01")
        .deviceType("WEB_SERVER")
        .confidence(100)
        .serviceRoles(serviceRoles)
        .build();
  }

  @Test
  void splitsCommaJoinedServiceRolesAndTrimsWhitespace() {
    when(repository.findByFileId(FILE)).thenReturn(List.of(host("10.0.0.1", "web, dns ,dhcp")));

    assertThat(adapter.hostFacts(FILE))
        .singleElement()
        .extracting(HostFacts::serviceRoles)
        .isEqualTo(List.of("web", "dns", "dhcp"));
  }

  @Test
  void absentServiceRolesBecomeEmptyListNotNull() {
    when(repository.findByFileId(FILE))
        .thenReturn(List.of(host("10.0.0.1", null), host("10.0.0.2", "  ")));

    assertThat(adapter.hostFacts(FILE)).extracting(HostFacts::serviceRoles).containsOnly(List.of());
  }

  @Test
  void byIpAndByMacLookupsMapThroughTheSameContract() {
    when(repository.findFirstByFileIdAndIpOrderByIdAsc(FILE, "10.0.0.1"))
        .thenReturn(Optional.of(host("10.0.0.1", "web")));
    when(repository.findFirstByFileIdAndMacIgnoreCaseOrderByIdAsc(eq(FILE), any()))
        .thenReturn(Optional.of(host("10.0.0.1", "web")));

    assertThat(adapter.hostFactsByIp(FILE, "10.0.0.1"))
        .get()
        .satisfies(
            h -> {
              assertThat(h.ip()).isEqualTo("10.0.0.1");
              assertThat(h.deviceType()).isEqualTo("WEB_SERVER");
              assertThat(h.serviceRoles()).isEqualTo(List.of("web"));
            });
    assertThat(adapter.hostFactsByMac(FILE, "02:00:00:00:00:01"))
        .get()
        .extracting(HostFacts::serviceRoles)
        .isEqualTo(List.of("web"));
  }

  @Test
  void missingHostIsEmptyOptional() {
    when(repository.findFirstByFileIdAndIpOrderByIdAsc(FILE, "10.0.0.9"))
        .thenReturn(Optional.empty());
    assertThat(adapter.hostFactsByIp(FILE, "10.0.0.9")).isEmpty();
  }
}
