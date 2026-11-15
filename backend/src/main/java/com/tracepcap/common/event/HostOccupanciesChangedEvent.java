package com.tracepcap.common.event;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * An analyst split or merged an address's devices (#918), so the per-device classifications and
 * identities changed. {@code starts} are the start times of the address's devices now, in order,
 * with null for the first. Labels on a device whose start is gone are moved to the device that now
 * covers that time, and adjudicators re-answer for the file.
 */
public record HostOccupanciesChangedEvent(UUID fileId, String ip, List<LocalDateTime> starts) {}
