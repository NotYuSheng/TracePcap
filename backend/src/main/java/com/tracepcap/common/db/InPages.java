package com.tracepcap.common.db;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import org.springframework.data.domain.Limit;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Every row of a file mapped to a smaller record, read a page at a time. Loading them all as
 * entities first held the entities and the records at once: 200k hosts' entities (three JSON maps
 * each) beside their facts ran an investigation read out of heap (#1373). Each page is mapped and
 * let go before the next is read.
 *
 * <p>Pages are keyset, by id: {@code after} is null for the first page.
 */
public final class InPages {

  /** Rows per page. */
  public static final int SIZE = 5_000;

  private InPages() {}

  /**
   * @param page the next page after an id (null: from the start), at most {@code limit} rows, in
   *     id order
   * @param id a row's id, for the next page's {@code after}
   * @param entityManager the session to let the rows go from, or null (no session to clear)
   */
  public static <E, K, R> List<R> of(
      BiFunction<K, Limit, List<E>> page, Function<E, K> id, Function<E, R> map,
      EntityManager entityManager) {
    List<R> out = new ArrayList<>();
    K after = null;
    while (true) {
      List<E> rows = page.apply(after, Limit.of(SIZE));
      for (E e : rows) out.add(map.apply(e));
      release(entityManager, rows);
      if (rows.size() < SIZE) return out;
      after = id.apply(rows.get(rows.size() - 1));
    }
  }

  /**
   * Lets rows read only to be mapped leave the session, when one is open: outside a transaction
   * they're already detached. Pending changes are flushed first, so detaching one a caller had
   * modified loses nothing.
   */
  public static void release(EntityManager entityManager, List<?> rows) {
    if (entityManager == null || rows.isEmpty()) return;
    if (!TransactionSynchronizationManager.isActualTransactionActive()) return;
    if (!TransactionSynchronizationManager.isCurrentTransactionReadOnly()) entityManager.flush();
    rows.forEach(entityManager::detach);
  }
}
