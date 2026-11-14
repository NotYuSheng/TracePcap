package com.tracepcap.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class MacKindTest {

  @Test
  void hypervisorPrefixes_areVirtualMachines() {
    assertThat(MacKind.of("00:50:56:a1:3c:09")).isEqualTo(MacKind.VIRTUAL_MACHINE);
    assertThat(MacKind.hypervisor("00:50:56:a1:3c:09")).isEqualTo("VMware");
    assertThat(MacKind.of("08:00:27:00:00:01")).isEqualTo(MacKind.VIRTUAL_MACHINE);
    // QEMU's 52:54:00 has the locally-administered bit set; it's still a VM, not a private MAC.
    assertThat(MacKind.of("52:54:00:12:34:56")).isEqualTo(MacKind.VIRTUAL_MACHINE);
    assertThat(MacKind.of("00-15-5D-01-02-03")).isEqualTo(MacKind.VIRTUAL_MACHINE);
  }

  @Test
  void dockerPrefix_isAContainer_beforeItCountsAsPrivate() {
    assertThat(MacKind.of("02:42:ac:11:00:02")).isEqualTo(MacKind.CONTAINER);
  }

  @Test
  void theLocallyAdministeredBit_meansAPrivateMac() {
    assertThat(MacKind.of("3a:1f:9c:52:0e:11")).isEqualTo(MacKind.PRIVATE); // 0x3a has bit 0x02
    assertThat(MacKind.of("7e:02:41:9a:c3:07")).isEqualTo(MacKind.PRIVATE);
    assertThat(MacKind.of("f8:bc:12:00:00:01")).isEqualTo(MacKind.HARDWARE); // Dell
    assertThat(MacKind.of("8c:71:f8:00:00:02")).isEqualTo(MacKind.HARDWARE); // Samsung
  }

  @Test
  void notAMac_isTreatedAsHardware() {
    assertThat(MacKind.of(null)).isEqualTo(MacKind.HARDWARE);
    assertThat(MacKind.of("10.0.0.1")).isEqualTo(MacKind.HARDWARE);
  }

  @Test
  void failoverPairMacs_areVirtualRouters() {
    assertThat(MacKind.of("00:00:5e:00:01:0a")).isEqualTo(MacKind.VIRTUAL_ROUTER);
    assertThat(MacKind.of("00:00:0c:07:ac:01")).isEqualTo(MacKind.VIRTUAL_ROUTER);
    assertThat(MacKind.of("00:00:0c:9f:f0:01")).isEqualTo(MacKind.VIRTUAL_ROUTER);
  }
}
