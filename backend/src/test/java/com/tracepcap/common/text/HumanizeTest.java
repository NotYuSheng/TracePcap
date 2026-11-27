package com.tracepcap.common.text;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** The backend's one way to write sizes, spans and counts, in step with the frontend (#1340). */
class HumanizeTest {

  @Test
  void bytesMatchTheFrontendsFormatBytes_base1024TwoDecimalsClampedAtPetabytes() {
    assertThat(Humanize.bytes(0)).isEqualTo("0 B");
    assertThat(Humanize.bytes(1023)).isEqualTo("1023 B");
    assertThat(Humanize.bytes(1536)).isEqualTo("1.50 KB");
    assertThat(Humanize.bytes(2_000_000)).isEqualTo("1.91 MB"); // the PDF, the answers and the UI agree
    assertThat(Humanize.bytes(6L * 1024 * 1024)).isEqualTo("6.00 MB");
    assertThat(Humanize.bytes(3L << 40)).isEqualTo("3.00 TB");
    assertThat(Humanize.bytes(Long.MAX_VALUE)).endsWith(" PB");
    assertThat(Humanize.bytes(-2048)).isEqualTo("-2.00 KB");
    assertThat(Humanize.bytes(Long.MIN_VALUE)).startsWith("-").doesNotStartWith("--").endsWith(" PB");
  }

  @Test
  void aValueThatRoundsUpToTheNextUnitIsWrittenInIt() {
    assertThat(Humanize.bytes(1_048_575)).isEqualTo("1.00 MB");
    assertThat(Humanize.bytes(1_073_741_000)).isEqualTo("1.00 GB");
    assertThat(Humanize.bytes(1_048_000)).isEqualTo("1023.44 KB");
  }

  @Test
  void spansPickTheOneUnitThatReadsBest_asTheFrontendsFormatSpanDoes() {
    assertThat(Humanize.span(45_000)).isEqualTo("45 s");
    assertThat(Humanize.span(89_000)).isEqualTo("89 s");
    assertThat(Humanize.span(26 * 60_000L)).isEqualTo("26 min");
    assertThat(Humanize.span(125 * 60_000L)).isEqualTo("2.1 h");
    assertThat(Humanize.span(5 * 3_600_000L)).isEqualTo("5 h");
    assertThat(Humanize.span(17 * 86_400_000L)).isEqualTo("17 days");
    assertThat(Humanize.span(1 * 86_400_000L * 2)).isEqualTo("2 days");
    assertThat(Humanize.span(100 * 86_400_000L)).isEqualTo("3 months");
    assertThat(Humanize.span(3L * 365 * 86_400_000L)).isEqualTo("3 years");
    assertThat(Humanize.span(-5)).isEqualTo("0 s");
  }

  @Test
  void pluralsCountTheNoun() {
    assertThat(Humanize.plural(1, "conversation")).isEqualTo("1 conversation");
    assertThat(Humanize.plural(0, "host")).isEqualTo("0 hosts");
    assertThat(Humanize.plural(3, "weak ticket")).isEqualTo("3 weak tickets");
  }
}
