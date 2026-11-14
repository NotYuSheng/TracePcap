package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.entity.DhcpLeaseEntity;
import com.tracepcap.analysis.entity.IpMacObservationEntity;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;

/** A device that moved to another address within a capture. */
class DeviceMovesTest {

  private static final LocalDateTime T10 = LocalDateTime.of(2026, 11, 10, 10, 0);

  private static IpMacObservationEntity arp(String ip, String mac, int fromMin, int toMin) {
    return IpMacObservationEntity.builder().ip(ip).mac(mac).firstSeen(T10.plusMinutes(fromMin)).lastSeen(T10.plusMinutes(toMin)).build();
  }

  private static DhcpLeaseEntity lease(String ip, String mac, String name, int atMin) {
    return DhcpLeaseEntity.builder().ip(ip).mac(mac).hostname(name).firstSeen(T10.plusMinutes(atMin)).lastSeen(T10.plusMinutes(atMin)).build();
  }

  @Test
  void aMacThatLeftOneAddressForAnother_isAMove_withItsNamesAndTimes() {
    var moves = DeviceMoves.of(
        List.of(arp("10.0.0.50", "f8:bc:12:00:00:01", 0, 57), arp("10.0.0.73", "f8:bc:12:00:00:01", 65, 119)),
        List.of(lease("10.0.0.50", "f8:bc:12:00:00:01", "LAPTOP-ALICE", 0), lease("10.0.0.73", "f8:bc:12:00:00:01", "ALICE-WS01", 65)));
    assertThat(moves).singleElement().satisfies(m -> {
      assertThat(m.fromIp()).isEqualTo("10.0.0.50");
      assertThat(m.toIp()).isEqualTo("10.0.0.73");
      assertThat(m.fromHostname()).isEqualTo("LAPTOP-ALICE");
      assertThat(m.toHostname()).isEqualTo("ALICE-WS01");
      assertThat(m.left()).isEqualTo(T10.plusMinutes(57));
      assertThat(m.arrived()).isEqualTo(T10.plusMinutes(65));
      assertThat(m.evidence()).isEqualTo("DHCP lease");
    });
  }

  @Test
  void aMacOnTwoAddressesAtOnce_isMultiHomed_notAMove() {
    assertThat(DeviceMoves.of(
        List.of(arp("10.0.0.1", "00:11:22:33:44:01", 0, 120), arp("10.0.1.1", "00:11:22:33:44:01", 5, 110)), List.of()))
        .isEmpty();
  }

  @Test
  void aFailoverPairsSharedMac_isNeverAMove() {
    assertThat(DeviceMoves.of(
        List.of(arp("10.0.0.254", "00:00:5e:00:01:0a", 0, 10), arp("10.0.1.254", "00:00:5e:00:01:0a", 20, 30)), List.of()))
        .isEmpty();
  }

  @Test
  void threeAddressesInTurn_areTwoMoves() {
    var moves = DeviceMoves.of(
        List.of(arp("10.0.0.5", "aa:00:00:00:00:01", 0, 10), arp("10.0.0.6", "aa:00:00:00:00:01", 20, 30),
            arp("10.0.0.7", "aa:00:00:00:00:01", 40, 50)), List.of());
    assertThat(moves).extracting(DeviceMoves.Move::toIp).containsExactly("10.0.0.6", "10.0.0.7");
    assertThat(moves.get(0).evidence()).isEqualTo("ARP");
  }
}
