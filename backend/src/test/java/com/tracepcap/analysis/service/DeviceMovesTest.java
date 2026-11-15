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

  private static DeviceMoves.Sighting use(String mac, String ip, int fromMin, int toMin) {
    return new DeviceMoves.Sighting(mac, ip, T10.plusMinutes(fromMin), T10.plusMinutes(toMin));
  }

  @Test
  void comingBackToAnEarlierAddress_isTwoMoves_whenConversationsShowTheGap() {
    String mac = "f8:bc:12:00:00:01";
    // ARP spans alone overlap (A from 0 to 119 covers B), which reads as multi-homed...
    var arp = List.of(arp("10.0.0.50", mac, 0, 119), arp("10.0.0.73", mac, 40, 70));
    assertThat(DeviceMoves.of(arp, List.of())).isEmpty();
    // ...but its conversations show A unused while it was on B: it left and came back.
    var uses = List.of(use(mac, "10.0.0.50", 1, 35), use(mac, "10.0.0.73", 41, 69), use(mac, "10.0.0.50", 80, 118));
    var moves = DeviceMoves.of(arp, List.of(), uses);
    assertThat(moves).extracting(m -> m.fromIp() + ">" + m.toIp()).containsExactly("10.0.0.50>10.0.0.73", "10.0.0.73>10.0.0.50");
    assertThat(moves.get(0).arrived()).isEqualTo(T10.plusMinutes(40));
    assertThat(moves.get(1).left()).isEqualTo(T10.plusMinutes(70));
  }

  @Test
  void fourMovesBetweenThreeAddresses_areAllRaised() {
    String mac = "aa:00:00:00:00:02";
    var arp = List.of(arp("10.0.0.5", mac, 0, 100), arp("10.0.0.6", mac, 20, 80), arp("10.0.0.7", mac, 40, 50));
    var uses = List.of(use(mac, "10.0.0.5", 1, 15), use(mac, "10.0.0.6", 21, 35), use(mac, "10.0.0.7", 41, 49),
        use(mac, "10.0.0.6", 60, 79), use(mac, "10.0.0.5", 90, 99));
    assertThat(DeviceMoves.of(arp, List.of(), uses)).extracting(DeviceMoves.Move::toIp)
        .containsExactly("10.0.0.6", "10.0.0.7", "10.0.0.6", "10.0.0.5");
  }

  @Test
  void conversationsOnTwoAddressesAtOnce_isMultiHomed() {
    String mac = "00:11:22:33:44:02";
    var arp = List.of(arp("10.0.0.1", mac, 0, 120), arp("10.0.1.1", mac, 5, 110));
    var uses = List.of(use(mac, "10.0.0.1", 0, 60), use(mac, "10.0.1.1", 30, 90));
    assertThat(DeviceMoves.of(arp, List.of(), uses)).isEmpty();
  }

  @Test
  void flappingBackAndForth_isNotMoving() {
    String mac = "00:11:22:33:44:03";
    var arp = List.of(arp("10.0.0.1", mac, 0, 100), arp("10.0.1.1", mac, 1, 99));
    var uses = new java.util.ArrayList<DeviceMoves.Sighting>();
    for (int i = 0; i < 10; i++) uses.add(use(mac, i % 2 == 0 ? "10.0.0.1" : "10.0.1.1", i * 10 + 2, i * 10 + 3));
    assertThat(DeviceMoves.of(arp, List.of(), uses)).isEmpty();
  }

  @Test
  void routedTrafficCarryingTheRoutersMac_isNotTheRouterMoving() {
    String router = "00:1b:21:aa:00:01";
    var arp = List.of(arp("10.0.0.1", router, 0, 120));
    var uses = List.of(use(router, "93.184.216.34", 10, 11), use(router, "142.250.4.100", 20, 21), use(router, "10.0.0.1", 30, 31));
    assertThat(DeviceMoves.of(arp, List.of(), uses)).isEmpty();
  }

  @Test
  void aSparseConversationAcrossTheMoves_doesNotMakeItMultiHomed() {
    // DHCP renewals on the same ports, at 0 and at 45: one conversation, but only its ends are use.
    String mac = "f8:bc:12:00:00:09";
    var arp = List.of(arp("10.0.0.50", mac, 0, 45), arp("10.0.0.73", mac, 15, 15), arp("10.0.0.88", mac, 30, 30));
    var uses = List.of(
        new DeviceMoves.Sighting(mac, "10.0.0.50", T10, T10.plusMinutes(45), false),
        use(mac, "10.0.0.50", 1, 14), use(mac, "10.0.0.73", 16, 29), use(mac, "10.0.0.88", 31, 44), use(mac, "10.0.0.50", 46, 55));
    assertThat(DeviceMoves.of(arp, List.of(), uses)).extracting(m -> m.fromIp() + ">" + m.toIp())
        .containsExactly("10.0.0.50>10.0.0.73", "10.0.0.73>10.0.0.88", "10.0.0.88>10.0.0.50");
  }

  @Test
  void aConversationThatCarriesOnWithTheNextDevice_doesNotFakeAReturn() {
    // The router's ARP with 10.0.0.50 began with the laptop and went on with the phone that took
    // the address next; its end is the phone's, not the laptop's.
    String laptop = "f8:bc:12:00:00:01";
    var arp = List.of(arp("10.0.0.50", laptop, 0, 57), arp("10.0.0.73", laptop, 65, 118));
    var uses = List.of(
        new DeviceMoves.Sighting(laptop, "10.0.0.50", T10, T10.plusMinutes(118), false),
        use(laptop, "10.0.0.50", 5, 50), use(laptop, "10.0.0.73", 66, 110));
    assertThat(DeviceMoves.of(arp, List.of(), uses)).extracting(m -> m.fromIp() + ">" + m.toIp())
        .containsExactly("10.0.0.50>10.0.0.73");
  }
}
