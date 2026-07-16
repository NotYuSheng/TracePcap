package com.tracepcap.common.event;

import java.util.UUID;

/**
 * Published when a node role is created, updated, dismissed, or deleted for a file (#369). The
 * monitor listens for this to carry the change forward and re-validate the rest of that file's
 * network chain, so labelling a snapshot propagates immediately (not just at ingest).
 *
 * <p>Lives in {@code common} as shared vocabulary (#512 slice 3): the publisher ({@code insights})
 * and the consumer ({@code monitor}) sit on opposite sides of the Scan/Adjudicate loop, so the
 * event class in either module would recreate the cycle this event exists to avoid. This is the
 * loop rule from the architecture doc made concrete — an adjudication change re-entering scanning.
 */
public record NodeRoleChangedEvent(UUID fileId) {}
