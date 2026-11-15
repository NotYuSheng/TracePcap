package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.entity.HostTtlWindowEntity;
import com.tracepcap.analysis.entity.IpOccupancyEntity;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Which traffic belongs to which device on a reused address (#918 slice 2). */
class OccupancyClassificationServiceTest {

  private static final LocalDateTime T10 = LocalDateTime.of(2026, 11, 10, 10, 0);
  private static final LocalDateTime T11 = T10.plusHours(1);
  private static final LocalDateTime T12 = T10.plusHours(2);

  private static IpOccupancyEntity occ(LocalDateTime from, LocalDateTime to) {
    return IpOccupancyEntity.builder().startsAt(from).endsAt(to).build();
  }

  private static HostTtlWindowEntity ttl(int ttl, LocalDateTime first, LocalDateTime last, long packets) {
    return HostTtlWindowEntity.builder().ttl(ttl).firstSeen(first).lastSeen(last).packets(packets).build();
  }

  @Test
  void within_isHalfOpen_andAnUnknownTimeBelongsToTheFirstDevice() {
    IpOccupancyEntity laptop = occ(null, T11);
    IpOccupancyEntity phone = occ(T11, null);
    assertThat(OccupancyClassificationService.within(T10, laptop)).isTrue();
    assertThat(OccupancyClassificationService.within(T11, laptop)).isFalse();
    assertThat(OccupancyClassificationService.within(T11, phone)).isTrue();
    assertThat(OccupancyClassificationService.within(null, laptop)).isTrue();
    assertThat(OccupancyClassificationService.within(null, phone)).isFalse();
  }

  @Test
  void ttlFor_givesEachDeviceTheTtlItSent() {
    List<HostTtlWindowEntity> windows =
        List.of(ttl(128, T10, T11.minusMinutes(1), 300), ttl(64, T11, T12, 900));
    assertThat(OccupancyClassificationService.ttlFor(windows, occ(null, T11))).isEqualTo(128);
    assertThat(OccupancyClassificationService.ttlFor(windows, occ(T11, null))).isEqualTo(64);
  }

  @Test
  void ttlFor_prefersATtlThatStartedInsideTheStretch_overOneCarriedOverFromBefore() {
    // The laptop's TTL was last seen a moment after the boundary (a straggler packet); the phone's
    // own TTL started inside its stretch and wins even with fewer packets.
    List<HostTtlWindowEntity> windows =
        List.of(ttl(128, T10, T11.plusSeconds(5), 5000), ttl(64, T11.plusSeconds(1), T12, 40));
    assertThat(OccupancyClassificationService.ttlFor(windows, occ(T11, null))).isEqualTo(64);
  }

  @Test
  void ttlFor_isNullWhenNothingWasSentInTheStretch() {
    assertThat(OccupancyClassificationService.ttlFor(List.of(ttl(64, T10, T10.plusMinutes(5), 3)), occ(T11, null)))
        .isNull();
  }
}
