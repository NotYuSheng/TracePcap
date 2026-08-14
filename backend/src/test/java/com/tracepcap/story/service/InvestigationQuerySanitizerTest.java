package com.tracepcap.story.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.story.dto.InvestigationQuery;
import org.junit.jupiter.api.Test;

/**
 * The model-behaviour repairs that used to live inline in {@code InvestigationService.buildSpec},
 * now covered so #623 can retire them per-path instead of on faith.
 */
class InvestigationQuerySanitizerTest {

  private static InvestigationQuery.InvestigationQueryBuilder query() {
    return InvestigationQuery.builder().id("q1").label("test");
  }

  @Test
  void freeTextByteBoundsBesideSrcIpAreDropped() {
    // The failure this prevents: 4.2MB is 10.0.0.5's *total* across the capture, so as a
    // per-conversation floor it matches nothing and the hypothesis dies of no evidence.
    var sanitized =
        InvestigationQuerySanitizer.sanitize(
            query().srcIp("10.0.0.5").minBytes(4_200_000L).build(), false);

    assertThat(sanitized.query().getMinBytes()).isNull();
    assertThat(sanitized.query().getSrcIp()).isEqualTo("10.0.0.5");
  }

  @Test
  void freeTextByteBoundsBesideRiskTypeAreDropped() {
    var sanitized =
        InvestigationQuerySanitizer.sanitize(
            query().riskType("suspicious_entropy").maxBytes(9_000_000L).build(), false);

    assertThat(sanitized.query().getMaxBytes()).isNull();
    assertThat(sanitized.query().getRiskType()).isEqualTo("suspicious_entropy");
  }

  @Test
  void freeTextByteBoundsSurviveOnTheirOwn() {
    var sanitized =
        InvestigationQuerySanitizer.sanitize(
            query().protocol("TCP").minBytes(1_000L).maxBytes(5_000L).build(), false);

    assertThat(sanitized.query().getMinBytes()).isEqualTo(1_000L);
    assertThat(sanitized.query().getMaxBytes()).isEqualTo(5_000L);
  }

  @Test
  void schemaConstrainedByteBoundsAreHonouredBesideSrcIp() {
    // The tool declares these as per-conversation at the point of generation, so a value that
    // arrives through it is taken at face value rather than thrown away.
    var sanitized =
        InvestigationQuerySanitizer.sanitize(
            query().srcIp("10.0.0.5").minBytes(50_000L).build(), true);

    assertThat(sanitized.query().getMinBytes()).isEqualTo(50_000L);
  }

  @Test
  void unknownAppSentinelsMeanIsNullOnBothPaths() {
    // A JSON schema types appName as a string; it cannot stop the model choosing the string
    // "unknown". This repair outlives tool calling and applies to constrained queries too.
    for (String sentinel : new String[] {"UNKNOWN_APP", "unknown", "Unknown", "null", "", "  "}) {
      for (boolean constrained : new boolean[] {true, false}) {
        var sanitized =
            InvestigationQuerySanitizer.sanitize(query().appName(sentinel).build(), constrained);

        assertThat(sanitized.appNameIsNull())
            .as("sentinel '%s', schemaConstrained=%s", sentinel, constrained)
            .isTrue();
        assertThat(sanitized.query().getAppName()).isNull();
      }
    }
  }

  @Test
  void realAppNamesAreMatchedExactly() {
    var sanitized = InvestigationQuerySanitizer.sanitize(query().appName("TLS").build(), true);

    assertThat(sanitized.appNameIsNull()).isFalse();
    assertThat(sanitized.query().getAppName()).isEqualTo("TLS");
  }

  @Test
  void aQueryWithNoFiltersIsACatchAll() {
    var sanitized = InvestigationQuerySanitizer.sanitize(query().build(), true);

    assertThat(InvestigationQuerySanitizer.isCatchAll(sanitized)).isTrue();
  }

  @Test
  void sanitisingIntoUnknownAppIsNotACatchAll() {
    // appName is nulled by the sentinel rule but the query still constrains something —
    // "app nDPI could not identify" is a filter, and dropping it would silently lose the query.
    var sanitized = InvestigationQuerySanitizer.sanitize(query().appName("unknown").build(), false);

    assertThat(InvestigationQuerySanitizer.isCatchAll(sanitized)).isFalse();
  }

  @Test
  void sanitisingAwayTheOnlyFilterLeavesACatchAll() {
    var sanitized =
        InvestigationQuerySanitizer.sanitize(
            query().srcIp(null).minBytes(9_000_000L).riskType(null).build(), false);
    assertThat(InvestigationQuerySanitizer.isCatchAll(sanitized)).isFalse();

    var dropped =
        InvestigationQuerySanitizer.sanitize(
            query().riskType("beaconing").minBytes(9_000_000L).build(), false);
    // riskType itself survives, so this is still a real query — the drop never empties it silently
    assertThat(InvestigationQuerySanitizer.isCatchAll(dropped)).isFalse();
  }

  @Test
  void doesNotMutateTheModelsOriginalQuery() {
    InvestigationQuery original = query().srcIp("10.0.0.5").minBytes(4_200_000L).build();

    InvestigationQuerySanitizer.sanitize(original, false);

    assertThat(original.getMinBytes()).isEqualTo(4_200_000L);
  }
}
