package com.tracepcap.story.spi;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import java.util.List;
import java.util.UUID;

/**
 * The facts a {@link Scanner} may read, and the reason every scanner can share one signature (#512).
 *
 * <p>Before this existed, the eight detectors had five different {@code detect(..)} signatures
 * between them — {@code (fileId)}, {@code (fileId, totalBytes)}, {@code (List<ConversationEntity>)}
 * and so on. That is precisely why there was no registry: with no common interface there is nothing
 * to list-inject, so the runner had to name every detector by hand and adding one meant editing it.
 * A context object is what collapses five signatures into one.
 *
 * <p><b>Reads are shared and lazy.</b> Accessors memoise: ask for the conversations from eight
 * scanners and the database is read once. Ask from none and it is not read at all — a scanner that
 * only wants a count does not pay for a list it never looks at.
 *
 * <p><b>Growing this is expected.</b> When a new scanner needs a fact nobody has needed yet, add an
 * accessor here. That is the seam working, not a smell — the alternative is the scanner reaching
 * into a repository, which is what #512 exists to stop. What must <em>not</em> happen is a scanner
 * taking a bespoke parameter, because that reintroduces the signature drift this record exists to
 * remove.
 */
public interface ScanContext {

  /** The file being scanned. */
  UUID fileId();

  /** How many conversations the file holds. Cheap — counted in the database, not derived. */
  long totalConversations();

  /** Total bytes across the capture. Cheap — read from the analysis summary. */
  long totalBytes();

  /**
   * Every conversation in the file. Loaded once per scan run and shared across scanners; never null.
   */
  List<ConversationFacts> conversations();

  /**
   * The conversations that carried a TLS certificate — {@link #conversations()} filtered on a
   * present issuer.
   *
   * <p>Derived here rather than in each scanner that wants it, so "what counts as a TLS
   * conversation" has one answer across the suite instead of one per scanner.
   */
  List<ConversationFacts> tlsConversations();
}
