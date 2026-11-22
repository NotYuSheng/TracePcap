package com.tracepcap.extraction.service;

import com.tracepcap.extraction.repository.ExtractedFileRepository;
import com.tracepcap.extraction.spi.ExtractedFileLookup;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ExtractedFileLookupAdapter implements ExtractedFileLookup {

  private final ExtractedFileRepository repository;

  @Override
  @Transactional(readOnly = true)
  public List<ExtractedFileFacts> extractedFiles(UUID fileId) {
    return repository.findByFileIdOrderByCreatedAtAsc(fileId).stream()
        .map(
            e ->
                new ExtractedFileFacts(
                    e.getConversationId(),
                    e.getFilename(),
                    e.getMimeType(),
                    e.getFileSize(),
                    e.getSha256(),
                    e.getExtractionMethod(),
                    e.getSkippedReason() != null))
        .toList();
  }
}
