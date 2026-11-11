package com.tracepcap.common.event;

import java.util.UUID;

/**
 * Published when re-scoring detection rules' device-type votes changed a capture's machine
 * classifications (#925). Adjudicators re-answer, so the host identities follow.
 */
public record HostClassificationsRescoredEvent(UUID fileId) {}
