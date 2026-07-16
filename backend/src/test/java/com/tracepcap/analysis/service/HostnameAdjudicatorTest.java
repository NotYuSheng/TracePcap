package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.service.HostnameResolverService.Claim;
import com.tracepcap.analysis.service.HostnameResolverService.ResolvedHostname;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The adjudicator must reproduce the resolver's old write-time selection exactly (lowest source
 * priority wins; first claim wins ties) — the slice's contract is "same winners, losers survive".
 */
class HostnameAdjudicatorTest {

  private final HostnameAdjudicator adjudicator = new HostnameAdjudicator();

  @Test
  void dhcpOutranksMdnsNbnsAndReverseDns() {
    Map<String, ResolvedHostname> winners =
        adjudicator.adjudicate(
            List.of(
                new Claim("10.0.0.5", "printer-via-ptr", HostnameResolverService.SOURCE_REVERSE_DNS),
                new Claim("10.0.0.5", "printer-via-nbns", HostnameResolverService.SOURCE_NBNS),
                new Claim("10.0.0.5", "printer-via-dhcp", HostnameResolverService.SOURCE_DHCP),
                new Claim("10.0.0.5", "printer-via-mdns", HostnameResolverService.SOURCE_MDNS)));

    assertThat(winners.get("10.0.0.5").hostname()).isEqualTo("printer-via-dhcp");
    assertThat(winners.get("10.0.0.5").source()).isEqualTo(HostnameResolverService.SOURCE_DHCP);
  }

  @Test
  void equalPriority_firstClaimSeenWins() {
    // The old record() kept the equal-or-better source already recorded — order must decide.
    Map<String, ResolvedHostname> winners =
        adjudicator.adjudicate(
            List.of(
                new Claim("10.0.0.7", "first-name", HostnameResolverService.SOURCE_MDNS),
                new Claim("10.0.0.7", "second-name", HostnameResolverService.SOURCE_MDNS)));

    assertThat(winners.get("10.0.0.7").hostname()).isEqualTo("first-name");
  }

  @Test
  void conflictingClaims_bestSourceStillWins_evenWhenSeenLast() {
    Map<String, ResolvedHostname> winners =
        adjudicator.adjudicate(
            List.of(
                new Claim("10.0.0.9", "name-a", HostnameResolverService.SOURCE_NBNS),
                new Claim("10.0.0.9", "name-b", HostnameResolverService.SOURCE_DHCP)));

    assertThat(winners.get("10.0.0.9").hostname()).isEqualTo("name-b");
  }

  @Test
  void independentIps_eachGetTheirOwnWinner() {
    Map<String, ResolvedHostname> winners =
        adjudicator.adjudicate(
            List.of(
                new Claim("10.0.0.1", "gw", HostnameResolverService.SOURCE_DHCP),
                new Claim("10.0.0.2", "nas", HostnameResolverService.SOURCE_NBNS)));

    assertThat(winners).hasSize(2);
    assertThat(winners.get("10.0.0.1").hostname()).isEqualTo("gw");
    assertThat(winners.get("10.0.0.2").hostname()).isEqualTo("nas");
  }

  @Test
  void noClaims_noWinners() {
    assertThat(adjudicator.adjudicate(List.of())).isEmpty();
  }
}
