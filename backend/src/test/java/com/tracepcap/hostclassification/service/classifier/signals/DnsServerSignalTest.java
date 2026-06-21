package com.tracepcap.hostclassification.service.classifier.signals;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.HostProfile;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import java.util.Set;
import org.junit.jupiter.api.Test;

class DnsServerSignalTest {

  private final DnsServerSignal signal = new DnsServerSignal();

  private HostContext ctx(Set<String> roles) {
    return new HostContext("10.0.0.1", new HostProfile(), 64, null, null, null, null, roles);
  }

  @Test
  void dnsRole_votesDnsServerStrongly() {
    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(Set.of("dns")), board);

    assertThat(board.scores()).containsEntry(DeviceTypes.DNS_SERVER, DnsServerSignal.WEIGHT);
    assertThat(board.winner(DeviceTypes.UNKNOWN)).isEqualTo(DeviceTypes.DNS_SERVER);
  }

  @Test
  void dnsRole_outranksHeuristicServerVote() {
    ScoreBoard board = new ScoreBoard();
    board.add(DeviceTypes.SERVER, 35, "inbound-only");
    signal.contribute(ctx(Set.of("dns")), board);

    assertThat(board.winner(DeviceTypes.UNKNOWN)).isEqualTo(DeviceTypes.DNS_SERVER);
  }

  @Test
  void noDnsRole_addsNothing() {
    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(Set.of()), board);

    assertThat(board.scores()).isEmpty();
  }
}
