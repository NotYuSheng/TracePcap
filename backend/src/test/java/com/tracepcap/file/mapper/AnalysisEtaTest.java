package com.tracepcap.file.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.common.stage.DetectionEngineStatus;
import com.tracepcap.file.entity.FileEntity;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * The analysis ETA (#758 follow-on).
 *
 * <p>The old model was seconds-per-packet with no fixed term, which read <b>91 minutes</b> for a job
 * of roughly 36 and <b>10 seconds</b> for one that took 49 — the same missing constant, in opposite
 * directions. Measured cost per 1000 packets fell ~8x between a 250-packet capture and a 45,000
 * packet one, because a large fixed cost was being amortised as if it scaled.
 *
 * <p>Tolerances are wide on purpose: this is about the model having the right shape, not about
 * freezing constants. Re-fit with {@code scripts/calibrate_analysis_eta.py} rather than nudging
 * numbers until the test passes.
 */
class AnalysisEtaTest {

  private final DetectionEngineStatus engine = mock(DetectionEngineStatus.class);
  private final FileMapper mapper = new FileMapper(engine);

  AnalysisEtaTest() {
    ReflectionTestUtils.setField(mapper, "suricataEnabled", true);
  }

  private FileEntity capture(int packets, long sizeBytes, boolean allStages) {
    FileEntity f = new FileEntity();
    f.setId(UUID.randomUUID());
    f.setPacketCount(packets);
    f.setFileSize(sizeBytes);
    f.setEnableNdpi(allStages);
    f.setEnableSuricata(allStages);
    f.setEnableFileExtraction(allStages);
    f.setStatus(FileEntity.FileStatus.COMPLETED);
    return f;
  }

  private Integer estimate(int packets, long sizeBytes, boolean warm) {
    when(engine.isWarm()).thenReturn(warm);
    return mapper.toMetadataDto(capture(packets, sizeBytes, true)).getEstimatedAnalysisSeconds();
  }

  @Test
  void matchesAMeasuredMidSizedRun() {
    // 20,000 packets / 17.4MB measured at 17.3s end to end.
    assertThat(estimate(20_000, 17_445_184L, true)).isBetween(10, 30);
  }

  @Test
  void matchesAMeasuredLargeRun() {
    // 45,000 packets / 39MB measured at ~44s.
    assertThat(estimate(45_000, 39_035_724L, true)).isBetween(25, 70);
  }

  @Test
  void doesNotUnderestimateASmallCapture() {
    // The failure seen live: a 45KB capture estimated at 10s took 49s. A tiny capture still pays
    // the fixed costs, so the floor must not collapse toward zero. FileMapper's MIN_ESTIMATE_SECONDS
    // is 10 — assert that floor directly rather than a weaker bound a regression could slip under.
    assertThat(estimate(250, 45_760L, true)).isGreaterThanOrEqualTo(10);
  }

  @Test
  void aColdEngineIsAMuchLongerJob() {
    // ~45s of ruleset build, paid once per process (#569). Ignoring it made a 47s first run look
    // like a 2s one.
    assertThat(estimate(2_000, 1_717_040L, false) - estimate(2_000, 1_717_040L, true))
        .isGreaterThan(30);
  }

  @Test
  void theEstimateGrowsWithPackets() {
    assertThat(estimate(45_000, 39_035_724L, true))
        .isGreaterThan(estimate(2_000, 1_717_040L, true));
  }

  @Test
  void aMillionPacketCaptureIsNoLongerPredictedAtNinetyMinutes() {
    // The report that started this: 1.7M packets predicted at 91m36s. Asserted as a ceiling, not a
    // target — the true figure at that size is unmeasured. This only pins that the old
    // 3.23 s/kpkt rate, which was mostly a mis-modelled fixed cost, is gone.
    assertThat(estimate(1_700_000, 468L * 1024 * 1024, true)).isLessThan(75 * 60);
  }

  @Test
  void disablingStagesMakesTheEstimateSmaller() {
    when(engine.isWarm()).thenReturn(true);
    Integer bare =
        mapper.toMetadataDto(capture(20_000, 17_445_184L, false)).getEstimatedAnalysisSeconds();

    assertThat(bare).isLessThan(estimate(20_000, 17_445_184L, true));
  }
}
