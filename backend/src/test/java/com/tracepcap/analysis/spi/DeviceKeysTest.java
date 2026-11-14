package com.tracepcap.analysis.spi;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;
import org.junit.jupiter.api.Test;

class DeviceKeysTest {

  private static final LocalDateTime T = LocalDateTime.of(2026, 11, 10, 11, 0, 1, 20_000_000);

  @Test
  void firstDeviceKeepsTheBareIp_laterOnesAreKeyedByStart() {
    assertThat(DeviceKeys.key("10.0.0.50", null)).isEqualTo("10.0.0.50");
    assertThat(DeviceKeys.key("10.0.0.50", T)).isEqualTo("10.0.0.50@2026-11-10T11:00:01.020");
  }

  @Test
  void roundTrips_andReadsIpv6() {
    String k = DeviceKeys.key("fe80::1", T);
    assertThat(DeviceKeys.isDeviceKey(k)).isTrue();
    assertThat(DeviceKeys.ipOf(k)).isEqualTo("fe80::1");
    assertThat(DeviceKeys.startOf(k)).isEqualTo(T);
    assertThat(DeviceKeys.isDeviceKey("fe80::1")).isFalse();
    assertThat(DeviceKeys.startOf("10.0.0.50")).isNull();
    assertThat(DeviceKeys.startOf("10.0.0.50@not-a-time")).isNull();
  }

  @Test
  void aDeviceOnAnotherNetwork_isIpTildeNetwork_andCanAlsoHaveAStart() {
    String k = DeviceKeys.key("192.168.1.10", "server:00:1b:21:bb:00:01", null);
    assertThat(k).isEqualTo("192.168.1.10~server:00:1b:21:bb:00:01");
    assertThat(DeviceKeys.isDeviceKey(k)).isTrue();
    assertThat(DeviceKeys.ipOf(k)).isEqualTo("192.168.1.10");
    assertThat(DeviceKeys.networkOf(k)).isEqualTo("server:00:1b:21:bb:00:01");
    assertThat(DeviceKeys.startOf(k)).isNull();
    String both = DeviceKeys.key("192.168.1.10", "vlan:20", T);
    assertThat(DeviceKeys.ipOf(both)).isEqualTo("192.168.1.10");
    assertThat(DeviceKeys.networkOf(both)).isEqualTo("vlan:20");
    assertThat(DeviceKeys.startOf(both)).isEqualTo(T);
  }
}
