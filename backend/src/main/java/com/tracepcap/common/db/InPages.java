package com.tracepcap.common.db;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import org.springframework.data.domain.Limit;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Every row of a file mapped to a smaller record, read a page at a time. Loading them all as
 * entities first held the entities and the records at once: 200k hosts' entities (three JSON maps
 * each) beside their facts ran an investigation read out of heap (#1373). Each page is mapped and
 * let go before the next is read.
 *
 * <p>Pages are keyset, by id: {@code after} is null for the first page. Rows come back in id order;
 * where two rows share a key, callers keep the first, as the {@code findFirst…OrderByIdAsc} lookups
 * do.
 *
 * <p>One snapshot: with no transaction open, the pages are read in one read-only REPEATABLE READ
 * transaction, so a re-analysis committing mid-read can't hand back half of each run. Inside a
 * caller's transaction they're read in it, at its isolation.
 *
 * <p>Inside a transaction, the rows read are detached once mapped (after one flush, so nothing
 * pending is lost). A caller must not hold one of these entities across the call and go on
 * modifying it: it's no longer managed.
 */
public final class InPages {

  /** Rows per page. */
  public static final int SIZE = 5_000;

  private InPages() {}

  /**
   * @param page the next page after an id (null: from the start), at most {@code limit} rows, in
   *     id order
   * @param id a row's id, for the next page's {@code after}
   * @param entityManager the session to let the rows go from, or null (no session)
   * @param transactions to open the snapshot when the caller has none, or null (no snapshot)
   */
  public static <E, K, R> List<R> of(
      BiFunction<K, Limit, List<E>> page, Function<E, K> id, Function<E, R> map,
      EntityManager entityManager, PlatformTransactionManager transactions) {
    if (transactions == null || TransactionSynchronizationManager.isActualTransactionActive()) {
      return read(page, id, map, entityManager);
    }
    TransactionTemplate snapshot = new TransactionTemplate(transactions);
    snapshot.setReadOnly(true);
    snapshot.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
    return snapshot.execute(status -> read(page, id, map, entityManager));
  }

  private static <E, K, R> List<R> read(
      BiFunction<K, Limit, List<E>> page, Function<E, K> id, Function<E, R> map,
      EntityManager entityManager) {
    boolean inSession = entityManager != null
        && TransactionSynchronizationManager.isActualTransactionActive();
    // Once, not per page: a flush dirty-checks the whole session.
    if (inSession && !TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
      entityManager.flush();
    }
    List<R> out = new ArrayList<>();
    K after = null;
    while (true) {
      List<E> rows = page.apply(after, Limit.of(SIZE));
      for (E e : rows) out.add(map.apply(e));
      if (inSession) rows.forEach(entityManager::detach);
      if (rows.size() < SIZE) return out;
      after = id.apply(rows.get(rows.size() - 1));
    }
  }

  /**
   * Every row of a file, a page at a time, for a caller that changes them: each page is flushed and
   * then let go before the next is read, so a rewrite of 200k hosts holds one page, not the file.
   * Needs a transaction (the writes must land in it). The rows are detached afterwards, so the
   * action must not hand one to anything that outlives its page.
   *
   * @param written rows the action saved alongside (audit entries, say), to let go with the page;
   *     the action adds to it, and it's emptied after each page. Null: none.
   */
  public static <E, K> void forEach(
      BiFunction<K, Limit, List<E>> page, Function<E, K> id, java.util.function.Consumer<E> action,
      EntityManager entityManager, java.util.Collection<Object> written) {
    if (!TransactionSynchronizationManager.isActualTransactionActive()) {
      throw new IllegalStateException("InPages.forEach writes, so it needs a transaction");
    }
    if (entityManager != null) entityManager.flush();
    K after = null;
    while (true) {
      List<E> rows = page.apply(after, Limit.of(SIZE));
      rows.forEach(action);
      if (entityManager != null) {
        // Only this page's rows and what was written with them are in the session to check.
        entityManager.flush();
        rows.forEach(entityManager::detach);
        if (written != null) written.forEach(w -> { if (w != null) entityManager.detach(w); });
      }
      if (written != null) written.clear();
      if (rows.size() < SIZE) return;
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
