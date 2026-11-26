package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** The settings the warm engine and the per-file run share (#1266). */
class SuricataSettingsTest {

  @Test
  void bothPathsInspectStreamsAlreadyOpenWhenTheCaptureBegan() {
    // Without it Suricata skips any TCP stream whose handshake isn't in the capture: on
    // PCAP-ATTACK's PsExec sample, no alerts at all instead of "ET INFO PsExec service created".
    assertThat(SuricataService.SHARED_SETTINGS).containsSequence("--set", "stream.midstream=true");
  }

  @Test
  void bothPathsInspectPacketsWhateverTheirChecksum() {
    // Offloaded checksums: Suricata's "auto" notices too late on a short capture, and drops the
    // packets from stream and protocol inspection until it does (SpoolSample: 0 alerts, not 6).
    assertThat(SuricataService.SHARED_SETTINGS)
        .containsSequence("--set", "pcap-file.checksum-checks=no")
        .containsSequence("--set", "stream.checksum-validation=no");
  }

  @Test
  void bothPathsKeepJa3() {
    assertThat(SuricataService.SHARED_SETTINGS).containsSequence("--set", SuricataService.JA3_ON);
  }
}
