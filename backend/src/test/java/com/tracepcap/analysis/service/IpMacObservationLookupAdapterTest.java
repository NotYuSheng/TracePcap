package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.entity.IpMacObservationEntity;
import com.tracepcap.analysis.repository.IpMacObservationRepository;
import com.tracepcap.analysis.spi.IpMacObservationLookup.IpMacs;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The port answers "which MACs claimed this IP" (#461) rather than handing back raw rows, so the
 * grouping is the adapter's contract — including the conflict case the feature exists to surface.
 */
class IpMacObservationLookupAdapterTest {

  private static final UUID FILE = UUID.randomUUID();

  private final IpMacObservationRepository repository = mock(IpMacObservationRepository.class);
  private final IpMacObservationLookupAdapter adapter =
      new IpMacObservationLookupAdapter(repository);

  private static IpMacObservationEntity obs(String ip, String mac) {
    return IpMacObservationEntity.builder().ip(ip).mac(mac).build();
  }

  @Test
  void groupsEveryMacThatClaimedTheSameIp() {
    when(repository.findByFileId(FILE))
        .thenReturn(
            List.of(
                obs("10.0.1.10", "ac:de:48:11:11:01"),
                obs("10.0.1.11", "ac:de:48:22:22:02"),
                obs("10.0.1.10", "52:54:00:b0:00:0a"))); // same IP, second claimant

    assertThat(adapter.ipMacObservations(FILE))
        .containsExactly(
            new IpMacs("10.0.1.10", List.of("ac:de:48:11:11:01", "52:54:00:b0:00:0a")),
            new IpMacs("10.0.1.11", List.of("ac:de:48:22:22:02")));
  }

  @Test
  void preservesFirstSeenOrderOfIps() {
    when(repository.findByFileId(FILE))
        .thenReturn(List.of(obs("10.0.0.3", "aa"), obs("10.0.0.1", "bb"), obs("10.0.0.2", "cc")));

    assertThat(adapter.ipMacObservations(FILE))
        .extracting(IpMacs::ip)
        .containsExactly("10.0.0.3", "10.0.0.1", "10.0.0.2");
  }

  @Test
  void noObservationsYieldsEmptyList() {
    when(repository.findByFileId(FILE)).thenReturn(List.of());
    assertThat(adapter.ipMacObservations(FILE)).isEmpty();
  }
}
