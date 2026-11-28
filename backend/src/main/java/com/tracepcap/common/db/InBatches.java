package com.tracepcap.common.db;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;

/**
 * A lookup by a list of keys, a batch of keys at a time. An {@code IN} binds one parameter per key:
 * Postgres takes at most 65,535 in one statement, and Hibernate builds a node per parameter, so a
 * scan capture's 200k addresses or conversations both failed the statement and ran the analysis out
 * of heap building it. Pass every caller-sized key list through here.
 */
public final class InBatches {

  /** Keys per statement: well under the bind limit, and a query plan Hibernate builds quickly. */
  public static final int SIZE = 5_000;

  private InBatches() {}

  /** {@code query} over each batch of {@code keys}, results concatenated in order. */
  public static <K, R> List<R> of(Collection<K> keys, Function<List<K>, ? extends Collection<R>> query) {
    if (keys == null || keys.isEmpty()) return List.of();
    List<K> all = keys instanceof List<K> l ? l : new ArrayList<>(keys);
    if (all.size() <= SIZE) return new ArrayList<>(query.apply(all));
    List<R> out = new ArrayList<>();
    for (int i = 0; i < all.size(); i += SIZE) {
      out.addAll(query.apply(all.subList(i, Math.min(all.size(), i + SIZE))));
    }
    return out;
  }
}
