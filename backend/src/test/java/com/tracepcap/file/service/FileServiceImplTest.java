package com.tracepcap.file.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.tracepcap.common.exception.PacketCountExceededException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the packet-count provisioning gate in {@link FileServiceImpl} (#827).
 *
 * <p>{@code enforcePacketLimit} only reads the three numeric config values, so the collaborators are
 * passed as {@code null} and no mocking is needed. The gate is the security-relevant surface: a
 * refactor that inverts the comparison, drops the disable guard, or breaks the size-gated
 * fail-closed branch must fail here rather than ship green.
 */
class FileServiceImplTest {

  private static final long MAX_FILE_SIZE = 500L * 1024 * 1024; // 500 MB
  private static final long MAX_PACKETS = 2_000_000L;
  private static final double VERIFY_FRACTION = 0.5; // fail closed at/above 250 MB
  private static final long VERIFY_THRESHOLD = (long) (MAX_FILE_SIZE * VERIFY_FRACTION);

  private static FileServiceImpl gateWith(long maxPackets, double verifyFraction) {
    return new FileServiceImpl(null, null, null, null, MAX_FILE_SIZE, maxPackets, verifyFraction);
  }

  private static FileServiceImpl defaultGate() {
    return gateWith(MAX_PACKETS, VERIFY_FRACTION);
  }

  @Nested
  class KnownCount {

    @Test
    void overLimit_throwsWithCountAndLimit() {
      assertThatThrownBy(() -> defaultGate().enforcePacketLimit(MAX_PACKETS + 1, 1L, "over.pcap"))
          .isInstanceOfSatisfying(
              PacketCountExceededException.class,
              ex -> {
                assertThat(ex.getPacketCount()).isEqualTo(MAX_PACKETS + 1);
                assertThat(ex.getMaxPackets()).isEqualTo(MAX_PACKETS);
              });
    }

    @Test
    void atLimit_passes() {
      // The check is strictly greater-than, so a capture exactly at the limit is accepted.
      assertThatCode(() -> defaultGate().enforcePacketLimit(MAX_PACKETS, 1L, "at.pcap"))
          .doesNotThrowAnyException();
    }

    @Test
    void underLimit_passes() {
      assertThatCode(() -> defaultGate().enforcePacketLimit(MAX_PACKETS - 1, 1L, "under.pcap"))
          .doesNotThrowAnyException();
    }

    @Test
    void underLimit_isNotAffectedByFileSize() {
      // A known under-limit count is accepted even for a huge file — size only matters when the
      // count is unknown. Guards against wiring the size branch into the known-count path.
      assertThatCode(() -> defaultGate().enforcePacketLimit(1L, MAX_FILE_SIZE, "big-but-few.pcap"))
          .doesNotThrowAnyException();
    }
  }

  @Nested
  class UnknownCount {

    @Test
    void largeFile_failsClosedAsUnverifiable() {
      assertThatThrownBy(() -> defaultGate().enforcePacketLimit(null, VERIFY_THRESHOLD, "big.pcap"))
          .isInstanceOfSatisfying(
              PacketCountExceededException.class,
              ex -> {
                assertThat(ex.getPacketCount())
                    .isEqualTo(PacketCountExceededException.UNKNOWN_COUNT);
                assertThat(ex.getMaxPackets()).isEqualTo(MAX_PACKETS);
              });
    }

    @Test
    void fileJustBelowThreshold_failsOpen() {
      assertThatCode(
              () -> defaultGate().enforcePacketLimit(null, VERIFY_THRESHOLD - 1, "small.pcap"))
          .doesNotThrowAnyException();
    }

    @Test
    void smallFile_failsOpen() {
      assertThatCode(() -> defaultGate().enforcePacketLimit(null, 1L, "tiny.pcap"))
          .doesNotThrowAnyException();
    }

    @Test
    void verifyFractionAtOrAboveOne_restoresPureFailOpen() {
      // fraction >= 1.0 is handled as an explicit "never fail closed" branch. This must hold even at
      // exactly maxFileSize — validateFile's check is strictly greater-than, so a file of exactly
      // that size reaches the gate, and a threshold-only implementation would wrongly reject it.
      FileServiceImpl pureFailOpen = gateWith(MAX_PACKETS, 1.0);
      assertThatCode(() -> pureFailOpen.enforcePacketLimit(null, MAX_FILE_SIZE, "huge.pcap"))
          .doesNotThrowAnyException();
    }
  }

  @Nested
  class Disabled {

    @Test
    void nonPositiveLimit_neverThrows_evenOverAnyPlausibleCount() {
      FileServiceImpl disabled = gateWith(0, VERIFY_FRACTION);
      assertThatCode(
              () -> disabled.enforcePacketLimit(Long.MAX_VALUE, MAX_FILE_SIZE, "whatever.pcap"))
          .doesNotThrowAnyException();
    }

    @Test
    void nonPositiveLimit_neverThrows_onUnknownCount() {
      FileServiceImpl disabled = gateWith(-1, VERIFY_FRACTION);
      assertThatCode(() -> disabled.enforcePacketLimit(null, MAX_FILE_SIZE, "whatever.pcap"))
          .doesNotThrowAnyException();
    }
  }

  @Nested
  class HugeCount {

    @Test
    void countAboveIntegerMax_isComparedAsLong_notOverflowed() {
      // Regression for the Integer.parseInt -> Long.parseLong fix: with the limit raised past
      // Integer.MAX_VALUE, a count above 2^31-1 but under the limit must be accepted (the long
      // comparison), not misread. And a count above the raised limit must still be rejected.
      long raisedLimit = 3_000_000_000L; // > Integer.MAX_VALUE
      FileServiceImpl bigGate = gateWith(raisedLimit, VERIFY_FRACTION);

      assertThatCode(() -> bigGate.enforcePacketLimit(2_500_000_000L, 1L, "under-raised.pcap"))
          .doesNotThrowAnyException();

      assertThatThrownBy(() -> bigGate.enforcePacketLimit(3_500_000_000L, 1L, "over-raised.pcap"))
          .isInstanceOf(PacketCountExceededException.class);
    }
  }
}
