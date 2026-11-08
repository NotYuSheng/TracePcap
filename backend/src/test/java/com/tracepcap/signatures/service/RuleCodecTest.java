package com.tracepcap.signatures.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.tracepcap.common.exception.FieldValidationException;
import com.tracepcap.signatures.dto.DetectionRuleRequest;
import com.tracepcap.signatures.dto.DetectionRuleRequest.Match;
import com.tracepcap.signatures.dto.DetectionRuleRequest.PayloadPattern;
import com.tracepcap.signatures.dto.DetectionRuleRequest.RegexPattern;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The rule shape (#925): validation messages, and the YAML format round-trips. */
class RuleCodecTest {

  private static DetectionRuleRequest.DetectionRuleRequestBuilder rule() {
    return DetectionRuleRequest.builder().name("r").severity("high");
  }

  @Test
  void aRuleNeedsAtLeastOneCriterion() {
    assertThat(RuleCodec.validate(rule().build())).containsKey("match");
    assertThat(RuleCodec.validate(rule().match(new Match()).build())).containsKey("match");
    assertThat(RuleCodec.validate(rule().match(Match.builder().dstPort(4444).build()).build())).isEmpty();
  }

  @Test
  void eachFieldIsCheckedWithAMessageForIt() {
    var errors =
        RuleCodec.validate(
            rule()
                .severity("urgent")
                .match(Match.builder().ip("example.com").cidr("10.0.0.0/33").srcPort(70000).ja3("abc").build())
                .payloadContains(List.of(PayloadPattern.builder().hex("4g").build(), new PayloadPattern()))
                .payloadRegex(List.of(RegexPattern.builder().pattern("(unclosed").build()))
                .build());
    assertThat(errors)
        .containsKeys(
            "severity", "match.ip", "match.cidr", "match.srcPort", "match.ja3",
            "payloadContains[0].hex", "payloadContains[1]", "payloadRegex[0].pattern");
    assertThat(errors.get("payloadRegex[0].pattern")).startsWith("Not a valid regular expression");
  }

  @Test
  void ipv6AndHexFormattingAreAccepted() {
    var r =
        rule()
            .match(Match.builder().ip("2001:db8::1").cidr("2001:db8::/32").build())
            .payloadContains(List.of(PayloadPattern.builder().hex("0x48:54 54-50").build()))
            .build();
    assertThat(RuleCodec.validate(r)).isEmpty();
  }

  @Test
  void readsAnOldSignaturesFile_andWritesTheSameRulesBack() {
    String old =
        """
        signatures:
          - name: c2_beacon
            description: Beacon to known C2
            severity: CRITICAL
            match:
              cidr: 203.0.113.0/24
              dstPort: "4444"
            payload_regex:
              - pattern: "beacon-[0-9]+"
                case_insensitive: true
            match_all: true
            device_type: "C2 Server"
          - description: no name, ignored by the old matcher
            match: {ip: 1.2.3.4}
        """;
    var parsed = RuleCodec.parseYaml(old);
    assertThat(parsed).hasSize(2);
    var r = parsed.get(0);
    assertThat(r.rule().getSeverity()).isEqualTo("critical");
    assertThat(r.rule().getMatch().getDstPort()).isEqualTo(4444);
    assertThat(r.rule().getPayloadRegex().get(0).isCaseInsensitive()).isTrue();
    assertThat(r.rule().isMatchAll()).isTrue();
    assertThat(r.deviceType()).isEqualTo("C2 Server");
    assertThat(parsed.get(1).rule().getName()).isNull();

    String exported = RuleCodec.formatYaml(List.of(RuleCodec.toYamlMap(r.rule(), r.deviceType())), "# h\n");
    var again = RuleCodec.parseYaml(exported).get(0);
    assertThat(again.rule()).isEqualTo(r.rule());
    assertThat(again.deviceType()).isEqualTo("C2 Server");
  }

  @Test
  void anUnparseablePortFailsValidationInsteadOfWideningTheRule() {
    var parsed = RuleCodec.parseYaml("signatures:\n  - name: x\n    match: {dstPort: http}\n");
    assertThat(RuleCodec.validate(parsed.get(0).rule())).containsKey("match.dstPort");
  }

  @Test
  void aDisabledRuleRoundTripsAsDisabled() {
    var r = rule().enabled(false).match(Match.builder().app("TOR").build()).build();
    String yaml = RuleCodec.formatYaml(List.of(RuleCodec.toYamlMap(r, null)), "");
    assertThat(yaml).contains("enabled: false");
    assertThat(RuleCodec.parseYaml(yaml).get(0).rule().isEnabled()).isFalse();
  }

  @Test
  void notYamlOrNotARulesFileIsAFieldError() {
    assertThatThrownBy(() -> RuleCodec.parseYaml("signatures: [unclosed"))
        .isInstanceOf(FieldValidationException.class);
    assertThatThrownBy(() -> RuleCodec.parseYaml("- just a list"))
        .isInstanceOfSatisfying(
            FieldValidationException.class, e -> assertThat(e.getErrors()).containsKey("content"));
    assertThat(RuleCodec.parseYaml("")).isEmpty();
    assertThat(RuleCodec.parseYaml("signatures:\n")).isEmpty();
  }
}
