package com.tracepcap.insights.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.GeoOrgLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.DeviceSpan;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import com.tracepcap.common.adjudication.HumanOverrideRepository;
import com.tracepcap.insights.repository.NodeRoleRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

/** Where a label carries to in the next monitor snapshot (#918 slice 3). */
class LabelCarryKeyTest {

  private final UUID prev = UUID.randomUUID();
  private final UUID next = UUID.randomUUID();
  private final HostClassificationLookup lookup = mock(HostClassificationLookup.class);
  private final LabelStalenessService service =
      new LabelStalenessService(
          mock(NodeRoleRepository.class), mock(HumanOverrideRepository.class), lookup,
          mock(GeoOrgLookup.class), mock(JdbcTemplate.class));

  private static HostFacts facts(String key, String mac) {
    return new HostFacts(key, mac, null, null, null, null, null, null, 0, null, "MOBILE", 60, List.of());
  }

  @Test
  void anAddressLabel_carriesByIp_asBefore() {
    when(lookup.deviceSpan(prev, "10.0.0.20")).thenReturn(Optional.empty());
    assertThat(service.carryKey("10.0.0.20", prev, next)).isEqualTo("10.0.0.20");
  }

  @Test
  void aDeviceLabel_followsItsMac_toWhereverTheDeviceIsNext() {
    String phone = "10.0.0.50@2026-11-10T11:00:01.020";
    when(lookup.deviceSpan(prev, phone)).thenReturn(Optional.of(new DeviceSpan("10.0.0.50", phone, 1, 2, null, null)));
    when(lookup.deviceFacts(prev, phone)).thenReturn(Optional.of(facts(phone, "8c:71:f8:00:00:02")));
    when(lookup.keyForMac(next, "8c:71:f8:00:00:02")).thenReturn(Optional.of("10.0.0.73"));
    assertThat(service.carryKey(phone, prev, next)).isEqualTo("10.0.0.73");
  }

  @Test
  void aDeviceNotInTheNextSnapshot_orAStaleDeviceKey_carriesNowhere() {
    String phone = "10.0.0.50@2026-11-10T11:00:01.020";
    when(lookup.deviceSpan(prev, phone)).thenReturn(Optional.of(new DeviceSpan("10.0.0.50", phone, 1, 2, null, null)));
    when(lookup.deviceFacts(prev, phone)).thenReturn(Optional.of(facts(phone, "8c:71:f8:00:00:02")));
    when(lookup.keyForMac(next, "8c:71:f8:00:00:02")).thenReturn(Optional.empty());
    assertThat(service.carryKey(phone, prev, next)).isNull();
    // A device key whose device was merged away in the previous snapshot.
    when(lookup.deviceSpan(prev, "10.0.0.60@2026-11-10T12:00")).thenReturn(Optional.empty());
    assertThat(service.carryKey("10.0.0.60@2026-11-10T12:00", prev, next)).isNull();
  }
}
