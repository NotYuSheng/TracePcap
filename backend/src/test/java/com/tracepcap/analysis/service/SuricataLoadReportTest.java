package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Suricata's own report of what it loaded (#1269): zero rules must not pass for a clean capture. */
class SuricataLoadReportTest {

  @Test
  void readsTheLoadLine_suricata6And8() {
    assertThat(SuricataEngine.parseLoad(
            "Info - 1 rule files processed. 53052 rules successfully loaded, 0 rules failed"))
        .isEqualTo(new SuricataEngine.LoadReport(53052, 0));
    assertThat(SuricataEngine.parseLoad(
            "i: detect: 1 rule files processed. 53073 rules successfully loaded, 2 rules failed, 0 rules skipped"))
        .isEqualTo(new SuricataEngine.LoadReport(53073, 2));
  }

  @Test
  void noRuleFiles_isZero() {
    SuricataEngine.LoadReport r = SuricataEngine.parseLoad(
        "W: detect: No rule files match the pattern /var/lib/suricata/rules/suricata.rules\n"
            + "W: detect: 1 rule files specified, but no rules were loaded!");
    assertThat(r.noRules()).isTrue();
  }

  @Test
  void noLoadLine_isUnknown() {
    assertThat(SuricataEngine.parseLoad("i: suricata: This is Suricata version 8.0.8 RELEASE")).isNull();
  }
}
