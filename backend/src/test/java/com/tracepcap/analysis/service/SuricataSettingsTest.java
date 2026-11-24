package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** The settings the warm engine and the per-file run share (#1266). */
class SuricataSettingsTest {

  @Test
  void bothPathsInspectStreamsAlreadyOpenWhenTheCaptureBegan() {
    // Without it Suricata skips any TCP stream whose handshake isn't in the capture: on
    // PCAP-ATTACK's PsExec sample, no alerts at all instead of "ET INFO PsExec service created".
    assertThat(SuricataService.SHARED_SETTINGS).containsSubsequence("--set", "stream.midstream=true");
  }

  @Test
  void bothPathsKeepJa3() {
    assertThat(SuricataService.SHARED_SETTINGS).containsSubsequence("--set", SuricataService.JA3_ON);
  }
}
