package com.tracepcap.intelligence.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.common.net.LocalityRules;
import com.tracepcap.intelligence.entity.CustomPrivateRangeEntity;
import com.tracepcap.intelligence.service.CustomPrivateRangeService.Override;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The operator's address configuration, now shared (#733 finding 2).
 *
 * <p>This precedence previously existed only inside {@code ChangeDetectionService}. An operator
 * could declare a range internal, watch change detection respect it, and watch the subnet view,
 * the story narrative and the cluster graph ignore it — three screens disagreeing with a fourth
 * about the same host.
 */
class CustomRangeLocalityPolicyTest {

  private final CustomPrivateRangeService ranges = mock(CustomPrivateRangeService.class);
  private final CustomRangeLocalityPolicy policy = new CustomRangeLocalityPolicy(ranges);

  private void overrideIs(Override verdict) {
    when(ranges.loadRanges()).thenReturn(List.of(new CustomPrivateRangeEntity()));
    when(ranges.overrideFor(anyString(), anyList())).thenReturn(verdict);
  }

  @Test
  void withNoOverridesItIsTheRfcHeuristic() {
    overrideIs(Override.NONE);

    LocalityRules rules = policy.currentRules();

    assertThat(rules.isLocal("10.0.0.1")).isTrue();
    assertThat(rules.isLocal("8.8.8.8")).isFalse();
  }

  @Test
  void anOverrideCanDeclareAPublicLookingAddressInternal() {
    overrideIs(Override.FORCE_PRIVATE);

    assertThat(policy.currentRules().isLocal("8.8.8.8")).isTrue();
  }

  @Test
  void anOverrideCanDeclareAPrivateLookingAddressExternal() {
    // The direction people forget. A lab using 10/8 for equipment they consider outside their
    // perimeter needs this, and it is why the override cannot be a simple "also private" list.
    overrideIs(Override.FORCE_PUBLIC);

    assertThat(policy.currentRules().isLocal("10.0.0.1")).isFalse();
  }

  @Test
  void extraCidrsWidenWhatCountsAsInternal() {
    overrideIs(Override.NONE);

    LocalityRules rules = policy.currentRules(ip -> ip.startsWith("100.64."));

    assertThat(rules.isLocal("100.64.0.1")).isTrue();
    assertThat(rules.isLocal("8.8.8.8")).isFalse();
  }

  @Test
  void anExtraCidrCannotOverturnAnOverrideDeclaringTheRangePublic() {
    // The precedence bug in the first draft of this design: expressing "extra CIDRs" as an OR on
    // top of the resolved answer let a per-snapshot subnet definition flip a range the operator
    // had explicitly declared public back to internal. Once the rules have said false there is no
    // way to tell an override from "the heuristic said no", so only this class can order them.
    overrideIs(Override.FORCE_PUBLIC);

    LocalityRules rules = policy.currentRules(ip -> true);

    assertThat(rules.isLocal("10.0.0.1")).isFalse();
  }

  @Test
  void aNullAddressIsNotInternal() {
    overrideIs(Override.NONE);

    assertThat(policy.currentRules().isLocal(null)).isFalse();
  }

  @Test
  void rulesAreResolvedOnceRatherThanPerAddress() {
    // currentRules() reads the ranges from the database and callers classify every host in a
    // capture. Resolving per address would be a query per address.
    overrideIs(Override.NONE);

    LocalityRules rules = policy.currentRules();
    rules.isLocal("10.0.0.1");
    rules.isLocal("10.0.0.2");
    rules.isLocal("8.8.8.8");

    verify(ranges, times(1)).loadRanges();
  }
}
