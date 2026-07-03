package com.tracepcap.insights.dto;

import java.util.List;

/**
 * Describes a carried-forward node-role label whose properties have drifted from the previous
 * snapshot's baseline (#369). Returned by {@code LabelStalenessService} so callers (e.g. monitor
 * change detection) can raise change events without depending on monitor types.
 */
public record LabelDrift(
    String entityType, String entityKey, String roleLabel, List<String> changedFields) {}
