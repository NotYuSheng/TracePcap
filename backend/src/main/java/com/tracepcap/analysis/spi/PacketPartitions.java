package com.tracepcap.analysis.spi;

import java.util.UUID;

/**
 * Write port for the physical partitions backing {@code packets} (#394).
 *
 * <p>{@code packets} is LIST-partitioned on {@code file_id}, one partition per file, so that
 * retention can reclaim a file's frames with a single {@code DROP TABLE} instead of a cascading
 * multi-million-row delete. That makes partition lifecycle a real step in the pipeline rather than
 * an invisible storage detail: a partition must exist before the first insert for a file, and
 * dropping it is how packet data is deleted.
 *
 * <p>This is a port rather than a repository method because the consumers sit outside {@code
 * analysis} — {@code cleanup} prunes on a schedule, and per {@code LayerDependencyTest} it must not
 * reach into {@code analysis.repository}. Everything here is DDL against a table {@code analysis}
 * owns; no other module should issue it directly.
 */
public interface PacketPartitions {

  /**
   * Ensures the partition holding {@code fileId}'s packets exists, creating it if not. Idempotent —
   * safe to call again for a file that already has one, including after a retry or a restart
   * mid-analysis.
   *
   * <p>Must be called before the first packet insert for a file: there is deliberately no default
   * partition, so an insert with no matching partition fails outright rather than landing rows
   * somewhere that cannot be dropped instantly.
   */
  void ensurePartition(UUID fileId);

  /**
   * Drops the partition holding {@code fileId}'s packets, discarding every frame for that file in
   * one O(1) unlink — no per-row deletes, no index maintenance, nothing left for autovacuum.
   *
   * <p>A no-op when the partition is already gone, so pruning and file deletion can both run
   * without coordinating. Returns {@code true} when a partition was actually dropped, letting
   * callers distinguish "pruned now" from "already pruned".
   */
  boolean dropPartition(UUID fileId);
}
