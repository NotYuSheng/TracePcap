package com.tracepcap.insights.dto;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Describes a confirmed node-role label whose underlying node properties have drifted from the
 * baseline captured at label time (#369). Returned by {@code LabelStalenessService} so callers
 * (e.g. monitor change detection) can raise change events without depending on monitor types.
 */
public record LabelDrift(
    String entityType,
    String entityKey,
    String roleLabel,
    LocalDateTime labeledAt,
    List<String> changedFields) {}
