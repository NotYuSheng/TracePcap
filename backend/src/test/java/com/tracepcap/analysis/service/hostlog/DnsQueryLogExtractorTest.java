package com.tracepcap.analysis.service.hostlog;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.service.hostlog.DnsQueryLogExtractor.QueryAgg;
import com.tracepcap.analysis.service.hostlog.DnsQueryLogExtractor.ServerStats;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link DnsQueryLogExtractor#parseRow} — the pure tshark-row parsing/aggregation
 * that underpins the DNS query log (#362). Fields are pipe-split:
 * {@code ip.src | dns.qry.name | dns.qry.type | dns.flags.rcode | dns.a | dns.aaaa | dns.count.answers}.
 */
class DnsQueryLogExtractorTest {

  private Map<String, QueryAgg> groups;
  private Map<String, ServerStats> serverStats;

  private void parse(
      String serverIp, String name, String qtype, String rcode, String a, String aaaa, String ancount) {
    if (groups == null) groups = new LinkedHashMap<>();
    if (serverStats == null) serverStats = new LinkedHashMap<>();
    DnsQueryLogExtractor.parseRow(
        new String[] {serverIp, name, qtype, rcode, a, aaaa, ancount}, groups, serverStats);
  }

  @Test
  void successfulQuery_isResolvable_withMappedTypeAndCode() {
    parse("10.0.0.1", "example.com", "1", "0", "93.184.216.34", "", "1");

    QueryAgg agg = groups.get("10.0.0.1|example.com|A");
    assertThat(agg).isNotNull();
    assertThat(agg.count).isEqualTo(1);
    assertThat(agg.resolvable).isTrue();
    assertThat(agg.responseCode).isEqualTo("NOERROR");
    assertThat(agg.resolvedIps).containsExactly("93.184.216.34");
  }

  @Test
  void nxdomainQuery_isNotResolvable_andCountsTowardServerStats() {
    parse("10.0.0.1", "nope.invalid", "1", "3", "", "", "0");

    QueryAgg agg = groups.get("10.0.0.1|nope.invalid|A");
    assertThat(agg.resolvable).isFalse();
    assertThat(agg.responseCode).isEqualTo("NXDOMAIN");
    assertThat(agg.resolvedIps).isEmpty();

    ServerStats stats = serverStats.get("10.0.0.1");
    assertThat(stats.totalResponses).isEqualTo(1);
    assertThat(stats.nxdomainResponses).isEqualTo(1);
  }

  @Test
  void repeatedQueries_aggregateCountAndUnionAnswers() {
    parse("10.0.0.1", "example.com", "1", "0", "1.1.1.1", "", "1");
    parse("10.0.0.1", "example.com", "1", "0", "2.2.2.2", "", "1");

    QueryAgg agg = groups.get("10.0.0.1|example.com|A");
    assertThat(agg.count).isEqualTo(2);
    assertThat(agg.resolvedIps).containsExactlyInAnyOrder("1.1.1.1", "2.2.2.2");
  }

  @Test
  void multipleAnswerRecordsInOneResponse_areAllKept() {
    parse("10.0.0.1", "cdn.example.com", "1", "0", "1.1.1.1,2.2.2.2", "", "2");

    QueryAgg agg = groups.get("10.0.0.1|cdn.example.com|A");
    assertThat(agg.resolvedIps).containsExactlyInAnyOrder("1.1.1.1", "2.2.2.2");
  }

  @Test
  void aaaaAnswers_areCaptured() {
    parse("10.0.0.1", "v6.example.com", "28", "0", "", "2606:2800:220:1::1", "1");

    QueryAgg agg = groups.get("10.0.0.1|v6.example.com|AAAA");
    assertThat(agg.responseCode).isEqualTo("NOERROR");
    assertThat(agg.resolvable).isTrue();
    assertThat(agg.resolvedIps).containsExactly("2606:2800:220:1::1");
  }

  @Test
  void nonAddressRecord_noErrorWithAnswer_isResolvable_withoutResolvedIps() {
    // An MX lookup that succeeds (NOERROR, ANCOUNT>0) carries no A/AAAA — still "resolved".
    parse("10.0.0.1", "example.com", "15", "0", "", "", "1");

    QueryAgg agg = groups.get("10.0.0.1|example.com|MX");
    assertThat(agg.responseCode).isEqualTo("NOERROR");
    assertThat(agg.resolvable).isTrue();
    assertThat(agg.resolvedIps).isEmpty();
  }

  @Test
  void noErrorWithZeroAnswers_isNodata_andNotResolvable() {
    // NOERROR but ANCOUNT=0 (e.g. a name that exists with no record of the queried type).
    parse("10.0.0.1", "empty.example.com", "1", "0", "", "", "0");

    QueryAgg agg = groups.get("10.0.0.1|empty.example.com|A");
    assertThat(agg.resolvable).isFalse();
  }

  @Test
  void unknownTypeAndRcode_fallBackToNumericLabels() {
    parse("10.0.0.1", "weird.example.com", "99", "11", "", "", "0");

    QueryAgg agg = groups.get("10.0.0.1|weird.example.com|TYPE99");
    assertThat(agg).isNotNull();
    assertThat(agg.responseCode).isEqualTo("RCODE11");
  }

  @Test
  void trailingDotInQueryName_isStripped() {
    parse("10.0.0.1", "example.com.", "1", "0", "1.1.1.1", "", "1");

    assertThat(groups).containsKey("10.0.0.1|example.com|A");
  }

  @Test
  void successfulAnswerWins_representativeResponseCode_overEarlierFailure() {
    // Same name/type: a SERVFAIL then a successful NOERROR — the success should win the row's code.
    parse("10.0.0.1", "flaky.example.com", "1", "2", "", "", "0");
    parse("10.0.0.1", "flaky.example.com", "1", "0", "9.9.9.9", "", "1");

    QueryAgg agg = groups.get("10.0.0.1|flaky.example.com|A");
    assertThat(agg.count).isEqualTo(2);
    assertThat(agg.resolvable).isTrue();
    assertThat(agg.responseCode).isEqualTo("NOERROR");
  }

  @Test
  void rowMissingServerOrName_isIgnored() {
    parse("", "example.com", "1", "0", "1.1.1.1", "", "1");
    parse("10.0.0.1", "", "1", "0", "1.1.1.1", "", "1");

    assertThat(groups).isNullOrEmpty();
  }

  @Test
  void serverStatsAccumulateAcrossQueries_forSuspicionScoring() {
    parse("10.0.0.9", "a.dga.test", "1", "3", "", "", "0");
    parse("10.0.0.9", "b.dga.test", "1", "3", "", "", "0");
    parse("10.0.0.9", "good.test", "1", "0", "1.1.1.1", "", "1");

    ServerStats stats = serverStats.get("10.0.0.9");
    assertThat(stats.totalResponses).isEqualTo(3);
    assertThat(stats.nxdomainResponses).isEqualTo(2);
  }
}
