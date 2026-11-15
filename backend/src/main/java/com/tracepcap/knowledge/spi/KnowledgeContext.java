package com.tracepcap.knowledge.spi;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * What one board assembly shares between its contributors: the file, and its facts loaded once
 * (#816).
 *
 * <p>Four contributors each called {@code conversationLookup.conversationFacts(fileId)}, so one
 * assembly streamed the whole conversation set from the database four times. Assembly runs on every
 * Analysis Overview render (its {@code /answers} call) and on every Q&A turn, so on a large capture
 * that was a lot of repeated I/O and heap. Each fact list here is loaded on first use, at most once
 * per assembly, and never if no contributor asks for it.
 *
 * <p>The lists are read-only because every contributor sees the same instance, so one can't
 * reorder or trim another's input.
 */
public final class KnowledgeContext {

  private final UUID fileId;
  private final Supplier<List<ConversationFacts>> conversationFacts;
  private final Supplier<List<HostFacts>> hostFacts;

  private KnowledgeContext(
      UUID fileId, Supplier<List<ConversationFacts>> conversations, Supplier<List<HostFacts>> hosts) {
    this.fileId = fileId;
    this.conversationFacts = memoize(conversations);
    this.hostFacts = memoize(hosts);
  }

  /** A context over these lookups. A null lookup reads as an empty list, for tests that need one. */
  public static KnowledgeContext of(
      UUID fileId, ConversationLookup conversations, HostClassificationLookup hosts) {
    return new KnowledgeContext(
        fileId,
        () -> conversations == null ? List.of() : conversations.conversationFacts(fileId),
        () -> hosts == null ? List.of() : hosts.hostFacts(fileId));
  }

  public UUID fileId() {
    return fileId;
  }

  /** Every conversation in the file. Loaded on first call, then shared. */
  public List<ConversationFacts> conversationFacts() {
    return conversationFacts.get();
  }

  /** Every classified host in the file. Loaded on first call, then shared. */
  public List<HostFacts> hostFacts() {
    return hostFacts.get();
  }

  /** Not thread-safe, and doesn't need to be: an assembly runs its contributors one at a time. */
  private static <T> Supplier<List<T>> memoize(Supplier<List<T>> loader) {
    return new Supplier<>() {
      private List<T> value;

      @Override
      public List<T> get() {
        if (value == null) {
          List<T> loaded = loader.get();
          value = loaded == null ? List.of() : List.copyOf(loaded);
        }
        return value;
      }
    };
  }
}
