package com.tracepcap.common.net;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * The one rule for per-network address configuration (#915 phase 4): a network's entries are
 * layered on the shared default, per CIDR.
 *
 * <ul>
 *   <li><b>Override:</b> a network entry for a CIDR the default has replaces it.
 *   <li><b>Add:</b> a network entry for a CIDR the default doesn't have.
 *   <li><b>Hide:</b> a hidden network entry removes the default's CIDR, and is itself left out.
 * </ul>
 *
 * The network's visible entries come first, then the default's remaining ones, each in the order
 * given, so a first-match reader prefers the network.
 */
public final class NetworkLayering {

  private NetworkLayering() {}

  public static <T> List<T> effective(
      List<T> defaults, List<T> network, Function<T, String> cidr, Predicate<T> hidden) {
    if (network == null || network.isEmpty()) return defaults == null ? List.of() : defaults;
    Set<String> taken = new HashSet<>();
    List<T> out = new ArrayList<>();
    for (T n : network) {
      taken.add(cidr.apply(n));
      if (!hidden.test(n)) out.add(n);
    }
    if (defaults != null) {
      for (T d : defaults) if (!taken.contains(cidr.apply(d))) out.add(d);
    }
    return out;
  }
}
