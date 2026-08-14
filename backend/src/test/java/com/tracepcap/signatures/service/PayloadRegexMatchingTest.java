package com.tracepcap.signatures.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.service.PcapParserService;
import java.lang.reflect.Method;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The {@code payload_regex} rule type (#341), which had no tests at all.
 *
 * <p>These patterns are written by operators into {@code signatures.yml} and then run against every
 * packet payload in a capture, so the interesting cases are the ones where a rule quietly matches
 * nothing, matches everything, or costs more than it should.
 */
class PayloadRegexMatchingTest {

  private final CustomSignatureService service = new CustomSignatureService();

  private static PcapParserService.PacketInfo packet(String ascii) {
    PcapParserService.PacketInfo p = new PcapParserService.PacketInfo();
    p.setPayload(HexFormat.of().formatHex(ascii.getBytes()));
    return p;
  }

  private static Map<String, Object> pattern(String regex) {
    return Map.of("pattern", regex);
  }

  private static Map<String, Object> pattern(String regex, boolean caseInsensitive) {
    return Map.of("pattern", regex, "case_insensitive", caseInsensitive);
  }

  @SuppressWarnings("unchecked")
  private boolean matches(
      List<PcapParserService.PacketInfo> packets,
      List<Map<String, Object>> patterns,
      boolean matchAll) {
    try {
      Method m =
          CustomSignatureService.class.getDeclaredMethod(
              "payloadRegexMatch", List.class, List.class, boolean.class);
      m.setAccessible(true);
      return (boolean) m.invoke(service, packets, patterns, matchAll);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("payloadRegexMatch changed — update this test", e);
    }
  }

  @Test
  void matchesAPatternAgainstTheDecodedPayload() {
    assertThat(matches(List.of(packet("GET /admin HTTP/1.1")), List.of(pattern("/admin")), false))
        .isTrue();
  }

  @Test
  void doesNotMatchWhenThePatternIsAbsent() {
    assertThat(matches(List.of(packet("GET / HTTP/1.1")), List.of(pattern("/admin")), false))
        .isFalse();
  }

  @Test
  void isCaseSensitiveUnlessAskedOtherwise() {
    // The flag is per entry, so a rule that omits it must not silently match anyway.
    assertThat(matches(List.of(packet("PASSWORD=hunter2")), List.of(pattern("password")), false))
        .isFalse();
    assertThat(
            matches(List.of(packet("PASSWORD=hunter2")), List.of(pattern("password", true)), false))
        .isTrue();
  }

  @Test
  void orSemanticsMatchWhenAnyPatternHits() {
    assertThat(
            matches(
                List.of(packet("GET /admin")),
                List.of(pattern("/nothing-here"), pattern("/admin")),
                false))
        .isTrue();
  }

  @Test
  void matchAllRequiresEveryPatternToHit() {
    // The distinction that makes a rule specific rather than noisy: with match_all a rule fires
    // only when every clause is present, so one clause missing must sink the whole rule.
    List<Map<String, Object>> both = List.of(pattern("/admin"), pattern("Cookie:"));
    assertThat(matches(List.of(packet("GET /admin\r\nCookie: x=1")), both, true)).isTrue();
    assertThat(matches(List.of(packet("GET /admin")), both, true)).isFalse();
  }

  @Test
  void aPatternMayMatchInAnyPacketOfTheConversation() {
    assertThat(
            matches(
                List.of(packet("HELO"), packet("GET /admin"), packet("BYE")),
                List.of(pattern("/admin")),
                false))
        .isTrue();
  }

  @Test
  void anInvalidPatternIsIgnoredRatherThanFailingTheAnalysis() {
    // Operator-written YAML. A typo must cost that one rule, not the whole capture.
    assertThat(matches(List.of(packet("anything")), List.of(pattern("(unclosed")), false))
        .isFalse();
  }

  @Test
  void aPacketWithNoPayloadIsSkipped() {
    PcapParserService.PacketInfo empty = new PcapParserService.PacketInfo();
    assertThat(matches(List.of(empty), List.of(pattern(".*")), false)).isFalse();
  }

  @Test
  void theClassicCatastrophicPatternsCompleteQuickly() {
    // The payload cap bounds input length, which is NOT a guard against catastrophic
    // backtracking — that is exponential in the pattern. This pins the empirical claim the
    // javadoc now makes: on this JDK's engine these complete fast. If a JDK change makes one of
    // them hang, this test hangs and says so, rather than the analysis pipeline doing it.
    String payload = "a".repeat(64) + "!";
    for (String bad : List.of("^(a+)+$", "(a|aa)+$", "(a|a?)+$", "(.*a){20}")) {
      long start = System.currentTimeMillis();
      matches(List.of(packet(payload)), List.of(pattern(bad)), false);
      assertThat(System.currentTimeMillis() - start)
          .as("pattern %s should not backtrack catastrophically", bad)
          .isLessThan(5_000);
    }
  }
}
