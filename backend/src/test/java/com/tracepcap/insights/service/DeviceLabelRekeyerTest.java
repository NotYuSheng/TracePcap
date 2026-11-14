package com.tracepcap.insights.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class DeviceLabelRekeyerTest {

  private static final LocalDateTime T10 = LocalDateTime.of(2026, 11, 10, 10, 0);

  @Test
  void covering_isTheLatestStartAtOrBefore_orTheFirstDevice() {
    var starts = Arrays.asList(null, T10.plusHours(1), T10.plusHours(3));
    assertThat(DeviceLabelRekeyer.covering(starts, T10.plusHours(2))).isEqualTo(T10.plusHours(1));
    assertThat(DeviceLabelRekeyer.covering(starts, T10.plusHours(3))).isEqualTo(T10.plusHours(3));
    assertThat(DeviceLabelRekeyer.covering(starts, T10.plusMinutes(30))).isNull();
  }
}
