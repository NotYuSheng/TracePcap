package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import java.util.Collection;

/** Cache writes that bypass the persistence context. */
public interface IpGeoInfoRepositoryCustom {

  /**
   * Inserts or refreshes these cache entries as one JDBC batch. Upsert, not insert: two analyses can
   * look up the same external IP at once, and a plain insert from the second violated the primary
   * key and, being inside the analysis transaction, aborted that whole analysis. Batched, and
   * outside the session: one modifying query per address flushed the session each time, and a
   * scan capture's 200k addresses took ten minutes.
   */
  void upsertAll(Collection<IpGeoInfoEntity> entries);
}
