package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.service.OccupancyBuilder.Decision;
import com.tracepcap.analysis.service.OccupancyBuilder.MacWindow;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;

class OccupancyBuilderTest {

  private static final LocalDateTime T = LocalDateTime.of(2026, 11, 8, 10, 0);

  private static LocalDateTime at(int minutes) {
    return T.plusMinutes(minutes);
  }

  @Test
  void oneMacIsOneOccupancy() {
    var r = OccupancyBuilder.build(List.of(new MacWindow("aa", at(0), at(60), "arp", null)), List.of(), true);
    assertThat(r.occupancies()).hasSize(1);
    assertThat(r.occupancies().get(0).mac()).isEqualTo("aa");
    assertThat(r.occupancies().get(0).startsAt()).isNull();
    assertThat(r.occupancies().get(0).endsAt()).isNull();
  }

  @Test
  void macsThatFollowOneAnotherSplit_withEvidence_andDhcpHostnames() {
    var r =
        OccupancyBuilder.build(
            List.of(
                new MacWindow("aa", at(0), at(59), "arp", null),
                new MacWindow("aa", at(1), at(2), "dhcp", "LAPTOP-ALICE"),
                new MacWindow("bb", at(60), at(120), "arp", null),
                new MacWindow("bb", at(61), at(61), "dhcp", "iPhone-Bob")),
            List.of(),
            true);
    assertThat(r.overlapping()).isFalse();
    assertThat(r.automaticBoundaries()).containsExactly(at(60));
    var o = r.occupancies();
    assertThat(o).hasSize(2);
    assertThat(o.get(0).hostname()).isEqualTo("LAPTOP-ALICE");
    assertThat(o.get(0).endsAt()).isEqualTo(at(60));
    assertThat(o.get(1).mac()).isEqualTo("bb");
    assertThat(o.get(1).hostname()).isEqualTo("iPhone-Bob");
    assertThat(o.get(1).startsAt()).isEqualTo(at(60));
    assertThat(o.get(1).startSource()).isEqualTo("arp");
    assertThat(o.get(1).startEvidence()).contains("aa last seen").contains("then bb from");
  }

  @Test
  void overlappingClaimsAreAConflict_notReuse_soNothingSplits() {
    var r =
        OccupancyBuilder.build(
            List.of(new MacWindow("aa", at(0), at(30), "arp", null), new MacWindow("bb", at(20), at(60), "arp", null)),
            List.of(),
            true);
    assertThat(r.overlapping()).isTrue();
    assertThat(r.occupancies()).hasSize(1);
  }

  @Test
  void virtualAddressesAndVirtualRouterMacsNeverSplitAutomatically() {
    var windows =
        List.of(new MacWindow("aa", at(0), at(10), "arp", null), new MacWindow("bb", at(20), at(30), "arp", null));
    assertThat(OccupancyBuilder.build(windows, List.of(), false).occupancies()).hasSize(1);
    var vrrp =
        List.of(
            new MacWindow("aa", at(0), at(10), "arp", null),
            new MacWindow("00:00:5e:00:01:0a", at(20), at(30), "arp", null));
    assertThat(OccupancyBuilder.build(vrrp, List.of(), true).occupancies()).hasSize(1);
  }

  @Test
  void aMergeRemovesTheAutomaticBoundary_andASplitAddsOne() {
    var windows =
        List.of(new MacWindow("aa", at(0), at(10), "arp", null), new MacWindow("bb", at(20), at(30), "arp", null));
    var merged = OccupancyBuilder.build(windows, List.of(new Decision(at(20), "merge", "alice", "MAC rotation")), true);
    assertThat(merged.occupancies()).hasSize(1);
    assertThat(merged.automaticBoundaries()).containsExactly(at(20)); // still reported, so it can be undone

    var split =
        OccupancyBuilder.build(
            List.of(new MacWindow("cc", at(0), at(30), "arp", null)),
            List.of(new Decision(at(15), "split", "alice", "cloned VM")),
            true);
    assertThat(split.occupancies()).hasSize(2);
    assertThat(split.occupancies().get(1).mac()).isEqualTo("cc"); // same MAC both sides
    assertThat(split.occupancies().get(1).startSource()).isEqualTo("manual");
    assertThat(split.occupancies().get(1).startEvidence()).isEqualTo("Split by alice: cloned VM");
  }

  @Test
  void aManualSplitWithNoEvidenceAtAll_offSubnetAddress() {
    var r = OccupancyBuilder.build(List.of(), List.of(new Decision(at(5), "split", null, "")), true);
    assertThat(r.occupancies()).hasSize(2);
    assertThat(r.occupancies().get(0).mac()).isNull();
    assertThat(r.occupancies().get(1).startEvidence()).isEqualTo("Split by an analyst");
  }

  @Test
  void splitsAndAutomaticBoundariesInterleaveInTimeOrder() {
    var windows =
        List.of(new MacWindow("aa", at(0), at(10), "arp", null), new MacWindow("bb", at(20), at(40), "arp", null));
    var r = OccupancyBuilder.build(windows, List.of(new Decision(at(30), "split", "bob", "re-imaged")), true);
    var o = r.occupancies();
    assertThat(o).hasSize(3);
    assertThat(o).extracting(OccupancyBuilder.Occupancy::idx).containsExactly(0, 1, 2);
    assertThat(o).extracting(OccupancyBuilder.Occupancy::mac).containsExactly("aa", "bb", "bb");
    assertThat(o).extracting(OccupancyBuilder.Occupancy::startSource).containsExactly(null, "arp", "manual");
  }
}
