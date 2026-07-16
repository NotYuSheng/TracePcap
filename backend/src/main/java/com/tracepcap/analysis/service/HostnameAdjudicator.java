package com.tracepcap.analysis.service;

import com.tracepcap.analysis.service.HostnameResolverService.Claim;
import com.tracepcap.analysis.service.HostnameResolverService.ResolvedHostname;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Picks each IP's display hostname from its recorded claims (#512 slice 4) — the Adjudicate-stage
 * counterpart of {@link HostnameResolverService}'s Extract-stage claim collection. Hosted in
 * {@code analysis} until a dedicated adjudicate module exists: the pipeline consumes the winners,
 * and {@code analysis} must not depend on feature modules (frozen ArchUnit rule).
 *
 * <p>Semantics are identical to the old write-time selection: lowest {@code SOURCE_PRIORITY} wins
 * per IP; the first claim seen wins ties. The difference is that losing claims now survive in
 * {@code hostname_claims}, so identity-conflict scanners (#511) have evidence to work with —
 * contested IPs (more than one distinct name claimed) are counted and logged here.
 */
@Slf4j
@Component
public class HostnameAdjudicator {

  /** Lower value = more authoritative for a host's own identity; the lowest wins per IP. */
  private static final Map<String, Integer> SOURCE_PRIORITY =
      Map.of(
          HostnameResolverService.SOURCE_MANUAL, 0,
          HostnameResolverService.SOURCE_DHCP, 1,
          HostnameResolverService.SOURCE_MDNS, 2,
          HostnameResolverService.SOURCE_NBNS, 3,
          HostnameResolverService.SOURCE_REVERSE_DNS, 4);

  /** The per-IP winners, preserving the old first-seen-wins tie behaviour. */
  public Map<String, ResolvedHostname> adjudicate(Collection<Claim> claims) {
    Map<String, ResolvedHostname> winners = new LinkedHashMap<>();
    Set<String> contested = new LinkedHashSet<>();

    for (Claim claim : claims) {
      ResolvedHostname existing = winners.get(claim.ip());
      if (existing == null) {
        winners.put(claim.ip(), new ResolvedHostname(claim.hostname(), claim.source()));
        continue;
      }
      if (!existing.hostname().equalsIgnoreCase(claim.hostname())) {
        contested.add(claim.ip());
      }
      if (SOURCE_PRIORITY.getOrDefault(existing.source(), Integer.MAX_VALUE)
          <= SOURCE_PRIORITY.getOrDefault(claim.source(), Integer.MAX_VALUE)) {
        continue; // keep the equal-or-better source already recorded
      }
      winners.put(claim.ip(), new ResolvedHostname(claim.hostname(), claim.source()));
    }

    if (!contested.isEmpty()) {
      log.info(
          "Hostname adjudication: {} of {} IP(s) contested (multiple distinct names claimed): {}",
          contested.size(),
          winners.size(),
          contested.stream().limit(5).toList());
    }
    return winners;
  }
}
