package com.tracepcap.analysis.service;

import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.spi.ConversationLookup;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Serves {@link ConversationLookup} from the analysis module's own repository. */
@Component
@RequiredArgsConstructor
public class ConversationLookupAdapter implements ConversationLookup {

  private final ConversationRepository repository;

  @Override
  public List<ConversationFacts> conversationFacts(UUID fileId) {
    return repository.findByFileId(fileId).stream()
        .map(
            e ->
                new ConversationFacts(
                    e.getProtocol(),
                    e.getStartTime(),
                    e.getEndTime(),
                    e.getPacketCount() == null ? 0 : e.getPacketCount(),
                    e.getTotalBytes() == null ? 0 : e.getTotalBytes()))
        .toList();
  }
}
