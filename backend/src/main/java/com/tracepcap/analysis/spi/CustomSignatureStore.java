package com.tracepcap.analysis.spi;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Write port for a capture's custom-signature labels (#925 phase 2). The {@code signatures} module
 * owns which rules matched which conversations; this column is the read model every view, filter
 * and report uses, so it's rewritten through here whenever the matches or the rules change.
 */
public interface CustomSignatureStore {

  /**
   * Sets the custom-signature names of every conversation in {@code fileId}: the given names for
   * conversations in {@code byConversation}, none for the rest. Must run inside a transaction.
   */
  void replaceForFile(UUID fileId, Map<UUID, List<String>> byConversation);
}
