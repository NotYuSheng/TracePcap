package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.file.entity.FileEntity;
import java.lang.reflect.Method;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Progress weighting (#758).
 *
 * <p>The bar's job is to distinguish "working" from "hung". It failed at that: the old weights put
 * the detection stage at 35% of the job when it was 95%, so the bar reached 23% almost immediately,
 * sat there for 44 seconds, then swept to 100% in under two.
 *
 * <p>These assert the shape rather than exact numbers — the numbers are measured shares and will be
 * re-measured when the pipeline changes, but the shape must hold: no stage may claim a share wildly
 * unlike what it costs, and the cold and warm profiles must genuinely differ.
 */
class StagePlanWeightingTest {

  private final SuricataEngine engine = mock(SuricataEngine.class);
  private final AnalysisService service = serviceWithOnlyTheEngineWired();

  /** 23 collaborators, one of which the plan needs; the rest are irrelevant to weighting. */
  private AnalysisService serviceWithOnlyTheEngineWired() {
    try {
      var ctor = AnalysisService.class.getDeclaredConstructors()[0];
      ctor.setAccessible(true);
      Object[] args = new Object[ctor.getParameterCount()];
      AnalysisService s = (AnalysisService) ctor.newInstance(args);
      ReflectionTestUtils.setField(s, "suricataEngine", engine);
      return s;
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("AnalysisService's constructor changed — update this test", e);
    }
  }

  private static FileEntity file(boolean suricata, boolean extraction) {
    FileEntity f = new FileEntity();
    f.setEnableSuricata(suricata);
    f.setEnableNdpi(true);
    f.setEnableFileExtraction(extraction);
    return f;
  }

  @SuppressWarnings("unchecked")
  private List<?> plan(FileEntity f) {
    try {
      Method m = AnalysisService.class.getDeclaredMethod("buildStagePlan", FileEntity.class);
      m.setAccessible(true);
      return (List<Object>) m.invoke(service, f);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("buildStagePlan changed — update this test", e);
    }
  }

  private int weightOf(Object step) {
    return (int) ReflectionTestUtils.invokeGetterMethod(step, "weight");
  }

  private String labelOf(Object step) {
    return (String) ReflectionTestUtils.invokeGetterMethod(step, "label");
  }

  private double shareOf(List<?> plan, String labelFragment) {
    int total = plan.stream().mapToInt(this::weightOf).sum();
    return plan.stream()
            .filter(s -> labelOf(s).contains(labelFragment))
            .mapToInt(this::weightOf)
            .sum()
        * 100.0
        / total;
  }

  @Test
  void onAColdEngineTheDetectionStageOwnsAlmostTheWholeBar() {
    // Measured: 94.7% of a 47s first-run analysis is the ruleset build. Anything close to an
    // even split here is what produced the 23%-for-95%-of-the-run stall.
    when(engine.isWarm()).thenReturn(false);

    assertThat(shareOf(plan(file(true, true)), "ruleset")).isGreaterThan(80.0);
  }

  @Test
  void onAWarmEngineTheWorkIsSpreadAcrossStages() {
    // Measured warm shares: parse 21%, detect 21%, classify 30%, extract-files 22%.
    when(engine.isWarm()).thenReturn(true);
    List<?> plan = plan(file(true, true));

    assertThat(shareOf(plan, "Detecting")).isBetween(10.0, 35.0);
    assertThat(shareOf(plan, "Classifying")).isBetween(15.0, 45.0);
    assertThat(shareOf(plan, "Parsing")).isBetween(10.0, 35.0);
  }

  @Test
  void theTwoProfilesAreActuallyDifferent() {
    // The bug this fixes is one vector describing two very different jobs.
    when(engine.isWarm()).thenReturn(false);
    double cold = shareOf(plan(file(true, true)), "ruleset");
    when(engine.isWarm()).thenReturn(true);
    double warm = shareOf(plan(file(true, true)), "Detecting");

    assertThat(cold - warm).isGreaterThan(40.0);
  }

  @Test
  void aColdEngineSaysWhyItIsSlowAndThatItIsOneOff() {
    // The bar cannot advance inside a stage, so this one is motionless for ~45s no matter how it
    // is weighted. The label is what separates "hung" from "working on something known to be
    // slow, once".
    when(engine.isWarm()).thenReturn(false);

    assertThat(plan(file(true, true)).stream().map(this::labelOf))
        .anySatisfy(l -> assertThat(l).containsIgnoringCase("first run"));
  }

  @Test
  void withSuricataOffTheColdPenaltyDoesNotApply() {
    // No ruleset to build, so the first capture looks like every other one.
    when(engine.isWarm()).thenReturn(false);

    assertThat(shareOf(plan(file(false, true)), "Detecting")).isLessThan(35.0);
    assertThat(plan(file(false, true)).stream().map(this::labelOf))
        .noneSatisfy(l -> assertThat(l).containsIgnoringCase("first run"));
  }

  @Test
  void theFileExtractionStageIsOnlyPlannedWhenItWillRun() {
    when(engine.isWarm()).thenReturn(true);

    assertThat(plan(file(true, false))).hasSize(6);
    assertThat(plan(file(true, true))).hasSize(7);
  }

  @Test
  void noStageIsWeightedZeroSoTheBarNeverStandsStill() {
    // A zero-weight stage advances the bar by nothing while it runs, which reads as a hang.
    when(engine.isWarm()).thenReturn(true);

    assertThat(plan(file(true, true))).allSatisfy(s -> assertThat(weightOf(s)).isPositive());
  }
}
