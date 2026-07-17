package com.tracepcap.story.service;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.story.spi.ScanContext;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * The {@link ScanContext} handed to scanners for one file, reading through {@link
 * ConversationLookup}.
 *
 * <p>Not a Spring bean: one instance per scan run, holding that run's memoised reads. Single-threaded
 * by construction — the runner walks its scanners in turn — so the caching needs no synchronisation.
 */
final class LazyScanContext implements ScanContext {

  private final UUID fileId;
  private final long totalConversations;
  private final long totalBytes;
  private final Supplier<List<ConversationFacts>> conversations;
  private final Supplier<List<ConversationFacts>> tlsConversations;

  LazyScanContext(
      UUID fileId, long totalConversations, long totalBytes, ConversationLookup lookup) {
    this.fileId = fileId;
    this.totalConversations = totalConversations;
    this.totalBytes = totalBytes;
    this.conversations = memoise(() -> lookup.conversationFacts(fileId));
    // Derived from the memoised list, so asking for both reads the database once, not twice.
    this.tlsConversations =
        memoise(
            () ->
                this.conversations.get().stream()
                    .filter(c -> c.tls().tlsIssuer() != null)
                    .toList());
  }

  /** Runs the supplier at most once; later calls return the first result. */
  private static <T> Supplier<T> memoise(Supplier<T> delegate) {
    return new Supplier<>() {
      private boolean loaded;
      private T value;

      @Override
      public T get() {
        if (!loaded) {
          value = delegate.get();
          loaded = true;
        }
        return value;
      }
    };
  }

  @Override
  public UUID fileId() {
    return fileId;
  }

  @Override
  public long totalConversations() {
    return totalConversations;
  }

  @Override
  public long totalBytes() {
    return totalBytes;
  }

  @Override
  public List<ConversationFacts> conversations() {
    return conversations.get();
  }

  @Override
  public List<ConversationFacts> tlsConversations() {
    return tlsConversations.get();
  }
}
