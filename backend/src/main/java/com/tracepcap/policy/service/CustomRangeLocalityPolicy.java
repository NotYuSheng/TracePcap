package com.tracepcap.policy.service;

import com.tracepcap.common.net.IpLocality;
import com.tracepcap.common.net.LocalityPolicy;
import com.tracepcap.common.net.LocalityRules;
import com.tracepcap.policy.entity.CustomPrivateRangeEntity;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Supplies the operator's address configuration to every module (#733 finding 2).
 *
 * <p>This layering already existed, inside {@code ChangeDetectionService}, and was reachable from
 * nowhere else. Moving it behind the port is the whole change: the precedence is unaltered.
 */
@Service
@RequiredArgsConstructor
public class CustomRangeLocalityPolicy implements LocalityPolicy {

  private final CustomPrivateRangeService customPrivateRangeService;

  @Override
  public LocalityRules currentRules() {
    return currentRules(null);
  }

  @Override
  public LocalityRules currentRules(LocalityRules.CidrSet additionalPrivate) {
    // Loaded once here rather than per address: the callers classify every host in a capture.
    List<CustomPrivateRangeEntity> overrides = customPrivateRangeService.loadRanges();
    return ip -> classify(ip, overrides, additionalPrivate);
  }

  private boolean classify(
      String ip, List<CustomPrivateRangeEntity> overrides, LocalityRules.CidrSet additionalPrivate) {
    if (ip == null) return false;
    // An operator override wins over the heuristic in either direction — that is the point of it,
    // and it is what lets a private-looking address be declared public and vice versa.
    switch (customPrivateRangeService.overrideFor(ip, overrides)) {
      case FORCE_PRIVATE -> {
        return true;
      }
      case FORCE_PUBLIC -> {
        return false;
      }
      case NONE -> {
        // fall through to the RFC ranges
      }
    }
    if (IpLocality.isLocal(ip)) return true;
    // Checked only after the overrides, so a range declared PUBLIC stays public.
    return additionalPrivate != null && additionalPrivate.contains(ip);
  }
}
