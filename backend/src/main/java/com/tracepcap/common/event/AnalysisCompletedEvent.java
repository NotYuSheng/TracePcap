package com.tracepcap.common.event;

import java.util.UUID;

/**
 * Published after a file's analysis transaction commits (#512 slice 5). Downstream stages
 * (adjudication in {@code insights} today) listen for it — the dependency stays feature → analysis
 * because the event lives in {@code common} and the pipeline never learns who is listening.
 */
public record AnalysisCompletedEvent(UUID fileId) {}
