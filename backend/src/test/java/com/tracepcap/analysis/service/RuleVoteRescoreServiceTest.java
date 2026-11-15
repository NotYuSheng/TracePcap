package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class RuleVoteRescoreServiceTest {

  @Test
  void analystLabelsMatchTheirType() {
    assertThat(RuleVoteRescoreService.labelMatches("IoT Device", "IOT")).isTrue();
    assertThat(RuleVoteRescoreService.labelMatches("Laptop / Desktop", "LAPTOP_DESKTOP")).isTrue();
    assertThat(RuleVoteRescoreService.labelMatches("PLC", "PLC")).isTrue();
    assertThat(RuleVoteRescoreService.labelMatches("PLC", "Badge Reader")).isFalse();
  }
}
