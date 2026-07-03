package com.tracepcap.insights.event;

import java.util.UUID;

/**
 * Published when a node role is created, updated, dismissed, or deleted for a file (#369). The
 * monitor listens for this to carry the change forward and re-validate the rest of that file's
 * network chain, so labelling a snapshot propagates immediately (not just at ingest).
 */
public record NodeRoleChangedEvent(UUID fileId) {}
