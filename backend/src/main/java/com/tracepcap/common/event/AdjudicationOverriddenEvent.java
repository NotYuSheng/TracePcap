package com.tracepcap.common.event;

import java.util.UUID;

/**
 * Published when a human overrides (or clears an override on) an adjudicated question for a file —
 * the generic counterpart of {@link NodeRoleChangedEvent}, keyed only by file because every
 * adjudicator re-answers on any human input (the runner does not need to know which question
 * changed).
 *
 * <p>Lives in {@code common} as shared vocabulary (#512 slice 3): the publisher (the generic
 * override service) and the consumer ({@link com.tracepcap.insights.service.AdjudicatorRunner}) must
 * not depend on each other's modules. Re-adjudication IS staleness — an override re-entering the
 * vote is the architecture's loop rule made concrete.
 */
public record AdjudicationOverriddenEvent(UUID fileId) {}
