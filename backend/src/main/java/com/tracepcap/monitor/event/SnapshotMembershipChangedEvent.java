package com.tracepcap.monitor.event;

import java.util.UUID;

/**
 * A capture joined or left a network (#925 phase 3). Published inside the change's transaction;
 * listeners that do work should run after commit. Lets other modules (detection rules) react
 * without the monitor module depending on them.
 */
public record SnapshotMembershipChangedEvent(UUID networkId, UUID fileId, boolean added) {}
