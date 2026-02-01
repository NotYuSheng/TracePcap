package com.tracepcap.file.event;

import com.tracepcap.analysis.service.AsyncAnalysisService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Listener for file upload events
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class FileUploadEventListener {

    private final AsyncAnalysisService asyncAnalysisService;

    /**
     * Triggered AFTER the upload transaction commits successfully
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleFileUploaded(FileUploadedEvent event) {
        log.info("File upload transaction committed, triggering async analysis for file: {}", event.getFileId());
        asyncAnalysisService.analyzeFileAsync(event.getFileId());
        log.info("Async analysis task submitted for file: {}", event.getFileId());
    }
}
